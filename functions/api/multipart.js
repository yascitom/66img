// ============================================================
// OSS 分片上传函数 —— EdgeOne Pages Functions / Cloudflare Pages Functions 通用版
// 路由：POST /api/multipart
// 原理：大文件走 OSS Multipart Upload（分片上传）：
//   1) action=init     服务端调用 InitiateMultipartUpload，返回 uploadId + key
//   2) action=part     服务端为单个分片签发「预签名 URL」（V1 URL 签名），
//                      浏览器拿 URL 直传该分片到 OSS，本函数不接触文件内容
//   3) action=complete 服务端调用 CompleteMultipartUpload 合并分片
//   4) action=abort    服务端调用 AbortMultipartUpload 清理残留分片
// 为什么能治「慢网速超过 10 分钟」：
//   每个分片的预签名 URL 都是「即签即传」、各自独立计时（默认 1 小时有效），
//   总上传时长不受任何单一签名有效期限制；失败的分片可单独重签重传，
//   已传成功的分片保存在 OSS 服务端，支持断点续传。
// 安全：密钥不出服务端；每个 action 都校验身份（密码或登录令牌）；
//       key 强制 upweb/ 前缀白名单 + 安全字符集，杜绝越权操作其他对象；
//       init 签发 HMAC 会话令牌绑定 key/uploadId/声明大小/分片上限，
//       complete 前 ListParts 逐片核验实际分片，防「声明小传大」与「检查后偷换分片」。
// 环境变量：与 sign.js 相同，新增（可选）：
//   PART_SIZE_MB  分片大小，默认 10（MB），范围 5~100
// ============================================================

const JSON_HEADERS = { 'Content-Type': 'application/json; charset=utf-8' };

function jsonResponse(obj, status = 200) {
  return new Response(JSON.stringify(obj), { status, headers: JSON_HEADERS });
}

async function hmacSha1Base64(secret, message) {
  const enc = new TextEncoder();
  const key = await crypto.subtle.importKey(
    'raw', enc.encode(secret),
    { name: 'HMAC', hash: 'SHA-1' },
    false, ['sign']
  );
  const sig = await crypto.subtle.sign('HMAC', key, enc.encode(message));
  return btoa(String.fromCharCode(...new Uint8Array(sig)));
}

function xmlUnescape(s) {
  return s
    .replace(/&lt;/g, '<')
    .replace(/&gt;/g, '>')
    .replace(/&quot;/g, '"')
    .replace(/&#39;|&apos;/g, "'")
    .replace(/&amp;/g, '&');
}

function xmlEscape(s) {
  return String(s)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

const IMG_EXTS = ['jpg', 'jpeg', 'png', 'gif', 'webp', 'svg', 'avif', 'bmp', 'ico', 'tiff'];
const VIDEO_EXTS = ['mp4', 'webm', 'mov', 'mkv', 'm4v', 'avi', 'flv', 'ts'];

// 文件主体名清洗：保留中日韩文字 / 字母数字 / . _ -，其余替换为 -，最长 80 字符（与 sign.js 一致）
function sanitizeBaseName(filename) {
  let base = String(filename).replace(/\.[^.]*$/, ''); // 去掉最后一个扩展名
  base = base.replace(/[\/\\]/g, '-');
  base = base.replace(/[^A-Za-z0-9._\-一-鿿㐀-䶿가-힯ㄱ-ㅣ぀-ヿ]/g, '-'); // 一-鿿 = CJK 基本区，㐀-䶿 = 扩展 A 区，가-힯 = 韩文音节，ㄱ-ㅣ = 韩文兼容字母，぀-ヿ = 日文假名
  base = base.replace(/-{2,}/g, '-').replace(/^[.\-]+|[.\-]+$/g, '');
  if (base.length > 80) base = base.slice(0, 80).replace(/[.\-]+$/, '');
  return base;
}

// 与 sign.js 同一套目录归类规则，保证两种上传方式落到相同路径
// keepName=true 时用清洗后的原文件名；否则用随机 UUID
function makeObjectKey(filename, keepName) {
  filename = String(filename || 'file.bin'); // 类型归一：防止非字符串入参抛 TypeError
  const ext = filename.includes('.') ? (filename.split('.').pop() || 'bin').toLowerCase().replace(/[^a-z0-9]/g, '').slice(0, 8) || 'bin' : 'bin';
  const dir = IMG_EXTS.includes(ext) ? 'upweb/img'
    : VIDEO_EXTS.includes(ext) ? 'upweb/video'
    : 'upweb/other';
  const d = new Date();
  const datePath = d.getFullYear() + String(d.getMonth() + 1).padStart(2, '0') + String(d.getDate()).padStart(2, '0');
  let base = keepName ? sanitizeBaseName(filename) : '';
  if (!base) base = crypto.randomUUID().replace(/-/g, '');
  return `${dir}/${datePath}/${base}.${ext}`;
}

// ------------------------------------------------------------
// 密码校验：SHA-256 哈希后再比对（避免长度/前缀泄露），
// 失败统一延迟 ~0.4s 再返回 401，拖慢在线暴力破解。
// ------------------------------------------------------------
async function sha256Hex(s) {
  const d = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(String(s == null ? '' : s)));
  return [...new Uint8Array(d)].map(b => b.toString(16).padStart(2, '0')).join('');
}

async function pwdOk(input, expected) {
  if (!expected) return true; // 仅在显式 ALLOW_ANONYMOUS_UPLOAD=true 的匿名模式下才会为空
  return (await sha256Hex(input)) === (await sha256Hex(expected));
}

async function rejectAuth() {
  await new Promise(r => setTimeout(r, 400));
  return jsonResponse({ error: '上传密码错误或会话已过期' }, 401);
}

// ============================================================
// 鉴权配置（fail-closed）与 HMAC 令牌（与 sign.js 相同实现）
// ============================================================
function authConfigError(env) {
  const p = env.UPLOAD_PASSWORD;
  if (!p) {
    if (String(env.ALLOW_ANONYMOUS_UPLOAD || '') === 'true') return '';
    return '服务端未配置 UPLOAD_PASSWORD，已拒绝服务。请在平台环境变量中设置上传密码（≥10 位）；如确需完全公开，显式设置 ALLOW_ANONYMOUS_UPLOAD=true';
  }
  if (String(p).length < 10) {
    return 'UPLOAD_PASSWORD 强度不足（至少需 10 位），已拒绝服务。请在平台环境变量中修改为强密码';
  }
  return '';
}

// 入参为 Latin-1 字节串（如 HMAC 签名）；含中日韩的 JSON 请用 b64urlJsonEncode
function b64urlEncode(s) { return btoa(s).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, ''); }

async function hmacSha256B64url(secret, message) {
  const enc = new TextEncoder();
  const key = await crypto.subtle.importKey('raw', enc.encode(secret), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  const sig = await crypto.subtle.sign('HMAC', key, enc.encode(message));
  return b64urlEncode(String.fromCharCode(...new Uint8Array(sig)));
}

// payload 可能含中日韩 key，JSON 编解码须走 UTF-8 字节（btoa/atob 只认 Latin-1）
function b64urlJsonEncode(o) {
  return b64urlEncode(String.fromCharCode(...new TextEncoder().encode(JSON.stringify(o))));
}
function b64urlJsonDecode(s) {
  const bin = atob(s.replace(/-/g, '+').replace(/_/g, '/'));
  return JSON.parse(new TextDecoder().decode(Uint8Array.from(bin, c => c.charCodeAt(0))));
}
async function makeToken(payload, secret) {
  const body = b64urlJsonEncode(payload);
  return body + '.' + (await hmacSha256B64url(secret, body));
}

async function readToken(token, secret) {
  if (typeof token !== 'string') return null;
  const i = token.lastIndexOf('.');
  if (i <= 0) return null;
  const body = token.slice(0, i);
  if ((await hmacSha256B64url(secret, body)) !== token.slice(i + 1)) return null;
  try {
    const p = b64urlJsonDecode(body);
    if (!p || typeof p.e !== 'number' || p.e < Math.floor(Date.now() / 1000)) return null;
    return p;
  } catch { return null; }
}

// 令牌派生密钥：HMAC(SK, 版本标识 | Bucket | 密码哈希)——改密码即作废全部令牌，
// 不同 Bucket 的部署实例令牌互不通用；与 sign.js 相同实现，不新增环境变量。
async function tokenKey(env) {
  const fp = await sha256Hex(env.UPLOAD_PASSWORD || '');
  return hmacSha256B64url(env.OSS_ACCESS_KEY_SECRET, 'yunwo-auth-v1|' + env.OSS_BUCKET + '|' + fp);
}

// 统一鉴权：返回 'pwd'（密码通过）/ 'token'（令牌通过）/ null（失败）
async function verifyAuth(body, env) {
  if (await pwdOk(body.password, env.UPLOAD_PASSWORD)) return 'pwd';
  const p = await readToken(body.auth, await tokenKey(env));
  return (p && p.t === 'auth') ? 'token' : null;
}

// 请求硬化：限制请求体与敏感字段长度（与 sign.js 相同实现）
function badInput(body) {
  if (!body || typeof body !== 'object') return '请求体必须是 JSON 对象';
  const limits = { password: 128, auth: 2048, session: 2048, token: 2048, filename: 256, uploadId: 256, mime: 128 };
  for (const k of Object.keys(limits)) {
    if (typeof body[k] === 'string' && body[k].length > limits[k]) return '参数非法';
  }
  if (Array.isArray(body.parts) && body.parts.length > 10000) return '参数非法';
  return '';
}
// 分片合并请求可能携带较多 ETag，上限放宽到 256KB
// 读取并校验请求体：Content-Length 超限走快路径直接 413（不用读 body）；
// 头缺失/不可信（chunked 分块传输没有此头）时按实际读入的字节数兜底，杜绝绕过
// 返回 { body } 或 { err: Response }
async function readJsonBody(request, cap) {
  const cl = parseInt(request.headers.get('Content-Length') || '0', 10);
  if (cl > cap) return { err: jsonResponse({ error: '请求体过大' }, 413) };
  let text;
  try {
    const buf = await request.arrayBuffer();
    if (buf.byteLength > cap) return { err: jsonResponse({ error: '请求体过大' }, 413) };
    text = new TextDecoder().decode(buf);
  } catch {
    return { err: jsonResponse({ error: '请求体读取失败' }, 400) };
  }
  try {
    return { body: JSON.parse(text) };
  } catch {
    return { err: jsonResponse({ error: '请求体必须是 JSON' }, 400) };
  }
}

// ------------------------------------------------------------
// 分片会话令牌：init 时签发，绑定 key/uploadId/声明大小/分片上限/分片尺寸，
// part/complete/abort 必须持有匹配的令牌，杜绝「声明小传大」与越权会话操作。
// ------------------------------------------------------------
const MP_TOKEN_TTL = 7 * 24 * 3600; // 与前端断点续传任务存活期一致

async function makeMpToken(env, key, uploadId, size, partSize) {
  return makeToken({
    t: 'mp',
    k: key,
    u: uploadId,
    s: size,                                   // 声明的文件总大小
    m: Math.ceil(size / partSize),             // 允许的最大分片数
    z: partSize,                               // 分片大小（complete 逐片核验用）
    e: Math.floor(Date.now() / 1000) + MP_TOKEN_TTL,
  }, await tokenKey(env));
}

// 校验会话令牌且与本次 key/uploadId 匹配；通过返回 payload，否则返回 null
async function mpSession(body, key, uploadId, env) {
  const p = await readToken(body.session, await tokenKey(env));
  if (!p || p.t !== 'mp' || p.k !== key || p.u !== uploadId) return null;
  return p;
}

function rejectSession() {
  return jsonResponse({ error: '分片会话无效或已过期，请重新选择文件上传', code: 'BAD_SESSION' }, 400);
}

// key 白名单校验：只允许 upweb/ 前缀 + 安全字符集（字母数字 / 中文 / . _ - /），
// 禁止 .. 和引号/尖括号等可注入字符，杜绝恶意 key 引发的存储型 XSS
const KEY_RE = /^upweb\/[A-Za-z0-9._\/\-一-鿿㐀-䶿가-힯ㄱ-ㅣ぀-ヿ]+$/;
function validKey(key) {
  return typeof key === 'string' && key.length <= 512 && KEY_RE.test(key) && !key.includes('..');
}

// 对象键逐段编码（保留 / 分隔符），用于拼接 URL 路径
function encodeKeyPath(key) {
  return key.split('/').map(encodeURIComponent).join('/');
}

// ------------------------------------------------------------
// 带超时与瞬时故障重试的 fetch：
// 边缘运行时（EO/ESA）到 OSS 的子请求偶发 net_exception_timeout 等网络抖动，
// 单次抖动不应判死一次已传了几十分钟的分片上传。仅网络层错误（含超时中止）重试；
// OSS 已应答的业务错误（4xx/NoSuchUpload/CONFLICT 等）不在此层处理，交由调用方判断。
// ------------------------------------------------------------
const OSS_FETCH_TIMEOUT_MS = 15000;
const OSS_FETCH_TRIES = 3;

async function fetchWithRetry(url, options) {
  let lastErr = null;
  for (let attempt = 1; attempt <= OSS_FETCH_TRIES; attempt++) {
    const ctrl = new AbortController();
    const timer = setTimeout(() => ctrl.abort(), OSS_FETCH_TIMEOUT_MS);
    try {
      return await fetch(url, Object.assign({}, options, { signal: ctrl.signal }));
    } catch (e) {
      lastErr = e;
      if (attempt < OSS_FETCH_TRIES) await new Promise(r => setTimeout(r, 400 * attempt));
    } finally {
      clearTimeout(timer);
    }
  }
  throw new Error('OSS 子请求连续失败（含超时重试）：' + ((lastErr && lastErr.message) || lastErr));
}

// ------------------------------------------------------------
// 服务端签名直调 OSS（init / complete / abort），V1 Header 签名
// + 签名自愈：若 OSS 返回 SignatureDoesNotMatch，用其错误 XML 中
//   <StringToSign>（OSS 按实际收到的请求算出的待签串）重签重试一次，
//   可自动适应边缘运行时对请求头的任何改写。
// ------------------------------------------------------------
async function ossRequest(env, method, key, subResource, contentType, bodyText, forbidOverwrite, extraHeaders) {
  const bucket = env.OSS_BUCKET;
  const endpoint = env.OSS_ENDPOINT;
  const url = `https://${bucket}.${endpoint}/${encodeKeyPath(key)}${subResource}`;

  const date = new Date().toUTCString();
  const canonicalizedResource = `/${bucket}/${key}${subResource}`;
  // x-oss- 头按名称字典序进入待签串：x-oss-date < x-oss-forbid-overwrite
  const ossHeaders = forbidOverwrite ? `x-oss-date:${date}\nx-oss-forbid-overwrite:true\n` : `x-oss-date:${date}\n`;
  const myStringToSign = `${method}\n\n${contentType || ''}\n\n${ossHeaders}${canonicalizedResource}`;

  const headers = {
    'x-oss-date': date,
    Authorization: `OSS ${env.OSS_ACCESS_KEY_ID}:${await hmacSha1Base64(env.OSS_ACCESS_KEY_SECRET, myStringToSign)}`,
  };
  if (forbidOverwrite) headers['x-oss-forbid-overwrite'] = 'true';
  if (contentType) headers['Content-Type'] = contentType;
  // extraHeaders 为不参与 V1 签名的普通请求头（如 Range），由调用方保证不含 x-oss- 前缀
  if (extraHeaders) Object.assign(headers, extraHeaders);

  let r = await fetchWithRetry(url, { method, headers, body: bodyText || undefined });
  let xml = await r.text();

  if (!r.ok) {
    const code = (xml.match(/<Code>([^<]+)<\/Code>/) || [])[1] || r.status;
    const ossString = (xml.match(/<StringToSign>([\s\S]*?)<\/StringToSign>/) || [])[1];

    if (code === 'SignatureDoesNotMatch' && ossString) {
      const ossStr = xmlUnescape(ossString);
      headers.Authorization = `OSS ${env.OSS_ACCESS_KEY_ID}:${await hmacSha1Base64(env.OSS_ACCESS_KEY_SECRET, ossStr)}`;
      r = await fetchWithRetry(url, { method, headers, body: bodyText || undefined });
      xml = await r.text();
      if (!r.ok) {
        const code2 = (xml.match(/<Code>([^<]+)<\/Code>/) || [])[1] || r.status;
        if (code2 === 'FileAlreadyExists') {
          const err = new Error('同名文件已存在，请先重命名或删除旧文件');
          err.code = 'CONFLICT';
          throw err;
        }
        // 签名排障细节（双方 StringToSign）只进平台日志，不进响应体
        console.error(`OSS ${method} 重签仍失败：`, code2, '｜OSS期望[', ossStr, ']｜我方[', myStringToSign, ']');
        throw new Error(`OSS ${method} 请求失败：` + code2);
      }
    } else if (code === 'FileAlreadyExists') {
      const err = new Error('同名文件已存在，请先重命名或删除旧文件');
      err.code = 'CONFLICT';
      throw err;
    } else {
      throw new Error(`OSS ${method} 请求失败：` + code);
    }
  }
  return xml;
}

// ------------------------------------------------------------
// 对象存在性检查：GET + Range: bytes=0-0（复用 ossRequest 的签名自愈与超时重试）
// 存在 → 206（1 字节 body）；不存在 → 404（NoSuchKey）；0 字节对象 → 416（InvalidRange，同样证明存在）。
// Range 是普通请求头，不参与 V1 签名计算；响应一律有 body，边缘运行时不会干等。
// ------------------------------------------------------------
async function ossObjectExists(env, key) {
  try {
    await ossRequest(env, 'GET', key, '', '', null, false, { Range: 'bytes=0-0' });
    return true; // 2xx（206 Partial Content）→ 存在
  } catch (e) {
    if (/NoSuchKey|404|NoSuchObject/.test(e.message)) return false;
    if (/InvalidRange|416/.test(e.message)) return true; // 0 字节对象：416 同样证明存在
    throw e;
  }
}

// ------------------------------------------------------------
// 为单个分片签发「预签名 URL」（V1 URL 签名，浏览器直传用）
// StringToSign = PUT\n\n{Content-Type}\n{Expires}\n/{bucket}/{key}?partNumber={n}&uploadId={id}
// （子资源按名称排序：partNumber < uploadId）
// 有效期 1 小时；每个分片即签即传，慢网速总时长不设限。
// ------------------------------------------------------------
async function signPartUrl(env, key, uploadId, partNumber, mime) {
  const bucket = env.OSS_BUCKET;
  const expires = Math.floor(Date.now() / 1000) + 3600;
  const stringToSign = `PUT\n\n${mime}\n${expires}\n/${bucket}/${key}?partNumber=${partNumber}&uploadId=${uploadId}`;
  const signature = await hmacSha1Base64(env.OSS_ACCESS_KEY_SECRET, stringToSign);

  const url = `https://${bucket}.${env.OSS_ENDPOINT}/${encodeKeyPath(key)}`
    + `?partNumber=${partNumber}&uploadId=${encodeURIComponent(uploadId)}`
    + `&OSSAccessKeyId=${encodeURIComponent(env.OSS_ACCESS_KEY_ID)}`
    + `&Expires=${expires}&Signature=${encodeURIComponent(signature)}`;
  return url;
}

async function handle(request, env) {
  if (request.method !== 'POST') {
    return jsonResponse({ error: 'Method Not Allowed' }, 405);
  }

  const required = ['OSS_ACCESS_KEY_ID', 'OSS_ACCESS_KEY_SECRET', 'OSS_BUCKET', 'OSS_ENDPOINT', 'PUBLIC_URL_BASE'];
  for (const k of required) {
    if (!env[k]) return jsonResponse({ error: `服务端缺少环境变量 ${k}` }, 500);
  }

  // 鉴权配置检查（fail-closed）：密码未配 / 弱密码 → 拒绝服务
  const cfgErr = authConfigError(env);
  if (cfgErr) return jsonResponse({ error: cfgErr }, 500);

  const { body, err } = await readJsonBody(request, 256 * 1024);
  if (err) return err;
  const inputErr = badInput(body);
  if (inputErr) return jsonResponse({ error: inputErr }, 400);

  // 所有分片操作都校验身份（密码或登录令牌，哈希比对 + 失败延迟）
  if (!(await verifyAuth(body, env))) {
    return rejectAuth();
  }

  const maxMB = parseInt(env.MAX_SIZE_MB, 10) || 100;
  const maxSize = maxMB * 1024 * 1024;
  let partMB = parseInt(env.PART_SIZE_MB, 10) || 10;
  if (partMB < 5) partMB = 5;
  if (partMB > 100) partMB = 100;
  const partSize = partMB * 1024 * 1024;

  const action = String(body.action || '');

  try {
    // ---------- 1) 初始化分片上传 ----------
    if (action === 'init') {
      const size = parseInt(body.size, 10) || 0;
      if (size <= 0 || size > maxSize) {
        return jsonResponse({ error: `文件大小超限（上限 ${maxMB}MB）` }, 400);
      }
      const mime = String(body.mime || 'application/octet-stream').slice(0, 100) || 'application/octet-stream';
      const key = makeObjectKey(body.filename || 'file.bin', body.keepName === true);

      // 保留原文件名时做存在性预检（提前 409，避免白传分片）；
      // complete 另带 x-oss-forbid-overwrite 硬兜底，堵住「预检→合并」时间窗内的静默覆盖。
      // 预检需要 RAM 授权 oss:GetObject。随机 UUID key 几乎不可能碰撞，跳过预检省一次请求。
      // ⚠️ 存在性检查的方式踩过两个坑，最终选 GET + Range: bytes=0-0：
      //  - GET ?objectMeta：200 响应头 Content-Length 是对象大小却无响应体，EO/ESA 边缘 fetch 干等 body 直至平台超时（net_exception_timeout）
      //  - HEAD（HeadObject）：本链路 403，且 HEAD 错误按 HTTP 语义无响应体，拿不到 OSS 错误码
      //  Range 是普通请求头不进 V1 签名；存在→206（1 字节 body 正常结束）、不存在→404（XML 错误体）、0 字节对象→416（同样证明存在）
      if (body.keepName === true) {
        if (await ossObjectExists(env, key)) {
          return jsonResponse({ error: `同名文件已存在：${key.split('/').pop()}（请先重命名或删除旧文件）`, code: 'CONFLICT' }, 409);
        }
      }

      const xml = await ossRequest(env, 'POST', key, '?uploads', mime, null);
      const uploadId = (xml.match(/<UploadId>([^<]+)<\/UploadId>/) || [])[1];
      if (!uploadId) throw new Error('OSS 未返回 UploadId');

      // 签发会话令牌：绑定本 key/uploadId、声明大小、分片数上限与分片尺寸
      const session = await makeMpToken(env, key, uploadId, size, partSize);

      return jsonResponse({
        key,
        uploadId,
        partSize,
        session,
        dir: key.split('/').slice(0, 2).join('/'),
      });
    }

    // ---------- 2) 为单个分片签发预签名 URL ----------
    if (action === 'part') {
      const key = String(body.key || '');
      const uploadId = String(body.uploadId || '');
      const partNumber = parseInt(body.partNumber, 10);
      if (!validKey(key) || !uploadId) {
        return jsonResponse({ error: '参数非法' }, 400);
      }
      if (!Number.isInteger(partNumber) || partNumber < 1 || partNumber > 10000) {
        return jsonResponse({ error: 'partNumber 须在 1~10000 之间' }, 400);
      }
      // 会话令牌：绑定 key/uploadId，且分片号不得超出 init 声明的分片数
      const mp = await mpSession(body, key, uploadId, env);
      if (!mp) return rejectSession();
      if (partNumber > mp.m) {
        return jsonResponse({ error: `分片号超出本会话上限（最多 ${mp.m} 片）`, code: 'BAD_SESSION' }, 400);
      }
      const mime = String(body.mime || 'application/octet-stream').slice(0, 100) || 'application/octet-stream';
      const url = await signPartUrl(env, key, uploadId, partNumber, mime);
      return jsonResponse({ url, expiresIn: 3600 });
    }

    // ---------- 3) 合并分片 ----------
    if (action === 'complete') {
      const key = String(body.key || '');
      const uploadId = String(body.uploadId || '');
      const parts = Array.isArray(body.parts) ? body.parts : [];
      if (!validKey(key) || !uploadId || parts.length === 0 || parts.length > 10000) {
        return jsonResponse({ error: '参数非法' }, 400);
      }
      // 会话令牌校验
      const mp = await mpSession(body, key, uploadId, env);
      if (!mp) return rejectSession();
      if (parts.length > mp.m) {
        return jsonResponse({ error: `分片数超出本会话上限（最多 ${mp.m} 片）`, code: 'BAD_SESSION' }, 400);
      }

      // ListParts 逐片核验：分片号 + ETag + 每片字节数必须与 init 声明完全吻合。
      // 只数总数不够——预签名 URL 在有效期内可重复 PUT 同号分片（OSS 允许覆盖），
      // 攻击者可在「检查」与「合并」之间偷换成大分片并提交新 ETag 绕过大小限制；
      // 逐片精确比对（含每片大小必须等于 partSize / 最后一片等于剩余字节）封死该路径。
      if (typeof mp.z !== 'number' || mp.z <= 0) {
        // 旧版会话令牌没有 partSize 字段：按会话失效处理，前端会自动重新 init
        return rejectSession();
      }
      const expectedSizeOf = n => (n < mp.m ? mp.z : mp.s - (mp.m - 1) * mp.z);
      const actual = new Map(); // partNumber -> { etag, size }
      let marker = 0;
      for (let guard = 0; guard < 20; guard++) {
        // 子资源按字母序：part-number-marker < uploadId
        const sub = marker
          ? `?part-number-marker=${marker}&uploadId=${encodeURIComponent(uploadId)}`
          : `?uploadId=${encodeURIComponent(uploadId)}`;
        const lp = await ossRequest(env, 'GET', key, sub, '', null);
        const partRe = /<Part>[\s\S]*?<PartNumber>(\d+)<\/PartNumber>[\s\S]*?<ETag>"?([0-9a-fA-F]+)"?<\/ETag>[\s\S]*?<Size>(\d+)<\/Size>[\s\S]*?<\/Part>/g;
        let pm;
        while ((pm = partRe.exec(lp)) !== null) {
          actual.set(parseInt(pm[1], 10), { etag: pm[2].toLowerCase(), size: parseInt(pm[3], 10) });
        }
        const truncated = /<IsTruncated>true<\/IsTruncated>/.test(lp);
        const next = (lp.match(/<NextPartNumberMarker>(\d+)<\/NextPartNumberMarker>/) || [])[1];
        if (!truncated || !next) break;
        marker = parseInt(next, 10);
      }
      let violation = actual.size !== parts.length;
      if (!violation) {
        for (const p of parts) {
          const n = parseInt(p.partNumber, 10);
          const etag = String(p.etag || '').replace(/"/g, '').toLowerCase();
          const a = actual.get(n);
          if (!a || a.etag !== etag || a.size !== expectedSizeOf(n)) { violation = true; break; }
        }
      }
      if (violation) {
        await ossRequest(env, 'DELETE', key, `?uploadId=${encodeURIComponent(uploadId)}`, '', null).catch(() => {});
        return jsonResponse({ error: '实际分片与 init 声明不一致（可能遭篡改），会话已清理', code: 'BAD_SESSION' }, 400);
      }

      let xmlBody = '<CompleteMultipartUpload>';
      for (const p of parts) {
        const n = parseInt(p.partNumber, 10);
        const etag = String(p.etag || '').replace(/"/g, '');
        if (!Number.isInteger(n) || n < 1 || n > 10000 || !etag) {
          return jsonResponse({ error: '分片列表参数非法' }, 400);
        }
        xmlBody += `<Part><PartNumber>${n}</PartNumber><ETag>"${xmlEscape(etag)}"</ETag></Part>`;
      }
      xmlBody += '</CompleteMultipartUpload>';

      // 合并：带 x-oss-forbid-overwrite 硬兜底，同名对象存在时 OSS 拒绝合并（409），绝不静默覆盖
      try {
        await ossRequest(env, 'POST', key, `?uploadId=${encodeURIComponent(uploadId)}`, 'application/xml', xmlBody, true);
      } catch (e) {
        // 「合并其实成功但响应丢失」场景：重试时 uploadId 已被消费，OSS 返回 NoSuchUpload。
        // 此时若对象已存在，说明上次合并已成功——按成功处理，避免前端整包重传。
        // 存在性检查方式见 ossObjectExists 注释（objectMeta 干等超时 / HEAD 403 两个坑）
        if (!/NoSuchUpload/.test(e.message)) throw e;
        if (!(await ossObjectExists(env, key))) throw e; // 对象不存在 → 会话确实已失效，抛原始错误
      }

      return jsonResponse({
        ok: true,
        key,
        url: `${env.PUBLIC_URL_BASE.replace(/\/$/, '')}/${encodeKeyPath(key)}`,
        dir: key.split('/').slice(0, 2).join('/'),
      });
    }

    // ---------- 4) 取消分片上传（清理残留分片，避免产生存储费） ----------
    if (action === 'abort') {
      const key = String(body.key || '');
      const uploadId = String(body.uploadId || '');
      if (!validKey(key) || !uploadId) {
        return jsonResponse({ error: '参数非法' }, 400);
      }
      // 会话令牌校验：只能取消自己的会话
      const mp = await mpSession(body, key, uploadId, env);
      if (!mp) return rejectSession();
      try {
        await ossRequest(env, 'DELETE', key, `?uploadId=${encodeURIComponent(uploadId)}`, '', null);
      } catch (e) {
        if (!/NoSuchUpload/.test(e.message)) throw e; // 会话已不存在（如已合并/已清理）视为取消成功
      }
      return jsonResponse({ ok: true });
    }

    return jsonResponse({ error: '未知 action（支持 init/part/complete/abort）' }, 400);
  } catch (e) {
    if (e.code === 'CONFLICT') return jsonResponse({ error: e.message, code: 'CONFLICT' }, 409);
    return jsonResponse({ error: e.message }, 502);
  }
}

// EdgeOne Pages Functions / Cloudflare Pages Functions 入口
export async function onRequestPost(context) {
  return handle(context.request, context.env);
}
export async function onRequest(context) {
  return handle(context.request, context.env);
}
