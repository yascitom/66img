// ============================================================
// OSS 直传签名 —— Cloudflare Workers 独立版（Module Worker）
// 路由：POST /api/sign、POST /api/list、POST /api/delete、POST /api/rename（改名/移动目录）、POST /api/multipart（大文件分片上传）、POST /api/upload（PicGo 兼容直传）
// 部署：Workers 控制台新建 Worker → 粘贴本文件 → Settings → Variables 配置环境变量
//       （也可直接 wrangler deploy）
// 前端 index.html 可托管在任何地方（CF Pages / EO Pages / 本地），
// 本 Worker 已放开 /api/* 的 CORS。
// 环境变量同 EO 版：OSS_ACCESS_KEY_ID / OSS_ACCESS_KEY_SECRET / OSS_BUCKET /
//                  OSS_ENDPOINT / PUBLIC_URL_BASE / UPLOAD_PASSWORD(必填，≥10 位) /
//                  ALLOW_ANONYMOUS_UPLOAD(可选，显式 true 才允许免密码) /
//                  MAX_SIZE_MB(可选) / PART_SIZE_MB(可选，分片大小，默认 10)
// ============================================================

const CORS = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Methods': 'POST, OPTIONS',
  'Access-Control-Allow-Headers': 'Content-Type',
};

function jsonResponse(obj, status = 200) {
  return new Response(JSON.stringify(obj), {
    status,
    headers: { 'Content-Type': 'application/json; charset=utf-8', ...CORS },
  });
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

// SHA-256 → hex（Web Crypto）
async function sha256Hex(s) {
  const d = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(String(s == null ? '' : s)));
  return [...new Uint8Array(d)].map(b => b.toString(16).padStart(2, '0')).join('');
}

// 密码校验：SHA-256 哈希后比对；失败统一延迟 ~0.4s，拖慢在线暴力破解
async function pwdOk(input, expected) {
  if (!expected) return true;
  return (await sha256Hex(input)) === (await sha256Hex(expected));
}
async function rejectAuth() {
  await new Promise(r => setTimeout(r, 400));
  return jsonResponse({ error: '上传密码错误或会话已过期' }, 401);
}

// ============================================================
// 鉴权配置（fail-closed）与 HMAC 令牌
// 未配置 UPLOAD_PASSWORD（且未显式 ALLOW_ANONYMOUS_UPLOAD=true）或
// 密码不足 10 位 → 所有接口返回 500 拒绝服务。
// 登录令牌（t:'auth'，7 天）代替前端保存明文密码；
// 分片会话令牌（t:'mp'）绑定 key/uploadId/声明大小/分片上限。
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

function b64urlEncode(s) { return btoa(s).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, ''); }
function b64urlDecode(s) { return atob(s.replace(/-/g, '+').replace(/_/g, '/')); }

async function hmacSha256B64url(secret, message) {
  const enc = new TextEncoder();
  const key = await crypto.subtle.importKey('raw', enc.encode(secret), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  const sig = await crypto.subtle.sign('HMAC', key, enc.encode(message));
  return b64urlEncode(String.fromCharCode(...new Uint8Array(sig)));
}

async function makeToken(payload, secret) {
  const body = b64urlEncode(JSON.stringify(payload));
  return body + '.' + (await hmacSha256B64url(secret, body));
}

async function readToken(token, secret) {
  if (typeof token !== 'string') return null;
  const i = token.lastIndexOf('.');
  if (i <= 0) return null;
  const body = token.slice(0, i);
  if ((await hmacSha256B64url(secret, body)) !== token.slice(i + 1)) return null;
  try {
    const p = JSON.parse(b64urlDecode(body));
    if (!p || typeof p.e !== 'number' || p.e < Math.floor(Date.now() / 1000)) return null;
    return p;
  } catch { return null; }
}

// 令牌派生密钥：HMAC(SK, 版本标识 | Bucket | 密码哈希)
// → 修改 UPLOAD_PASSWORD 立即作废全部已签发令牌；不同 Bucket 的部署实例令牌互不通用；
//   无需新增环境变量。
async function tokenKey(env) {
  const fp = await sha256Hex(env.UPLOAD_PASSWORD || '');
  return hmacSha256B64url(env.OSS_ACCESS_KEY_SECRET, 'yunwo-auth-v1|' + env.OSS_BUCKET + '|' + fp);
}

// 登录会话令牌：7 天硬到期、不续期——到期必须重新输入密码
const AUTH_TOKEN_TTL = 7 * 24 * 3600;
async function makeAuthToken(env) {
  return makeToken({ t: 'auth', e: Math.floor(Date.now() / 1000) + AUTH_TOKEN_TTL }, await tokenKey(env));
}

// 统一鉴权：返回 'pwd'（密码通过）/ 'token'（令牌通过）/ null（失败）
// 匿名模式（显式 ALLOW_ANONYMOUS_UPLOAD=true）下密码为空恒通过，返回 'pwd'
// 注意：令牌字段名用 auth，避免与 list 的分页游标 token 冲突
async function verifyAuth(body, env) {
  if (await pwdOk(body.password, env.UPLOAD_PASSWORD)) return 'pwd';
  const p = await readToken(body.auth, await tokenKey(env));
  return (p && p.t === 'auth') ? 'token' : null;
}

// 请求硬化：限制请求体与敏感字段长度，防畸形请求消耗函数资源
// （真正的按 IP 限流需在平台 WAF 层配置，见 README「安全提示」）
const MAX_BODY_BYTES = 8192;
function badInput(body) {
  if (!body || typeof body !== 'object') return '请求体必须是 JSON 对象';
  const limits = { password: 128, auth: 2048, session: 2048, token: 2048, filename: 256, dir: 16, uploadId: 256, mime: 128 };
  for (const k of Object.keys(limits)) {
    if (typeof body[k] === 'string' && body[k].length > limits[k]) return '参数非法';
  }
  return '';
}
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

const MP_TOKEN_TTL = 7 * 24 * 3600;
async function makeMpToken(env, key, uploadId, size, partSize) {
  return makeToken({
    t: 'mp', k: key, u: uploadId, s: size,
    m: Math.ceil(size / partSize),
    z: partSize, // 分片大小（complete 逐片核验用）
    e: Math.floor(Date.now() / 1000) + MP_TOKEN_TTL,
  }, await tokenKey(env));
}
async function mpSession(body, key, uploadId, env) {
  const p = await readToken(body.session, await tokenKey(env));
  if (!p || p.t !== 'mp' || p.k !== key || p.u !== uploadId) return null;
  return p;
}
function rejectSession() {
  return jsonResponse({ error: '分片会话无效或已过期，请重新选择文件上传', code: 'BAD_SESSION' }, 400);
}

const IMG_EXTS = ['jpg', 'jpeg', 'png', 'gif', 'webp', 'svg', 'avif', 'bmp', 'ico', 'tiff'];
const VIDEO_EXTS = ['mp4', 'webm', 'mov', 'mkv', 'm4v', 'avi', 'flv', 'ts'];

// 文件主体名清洗：保留中日韩文字 / 字母数字 / . _ -，其余替换为 -，最长 80 字符
function sanitizeBaseName(filename) {
  let base = String(filename).replace(/\.[^.]*$/, ''); // 去掉最后一个扩展名
  base = base.replace(/[\/\\]/g, '-');
  base = base.replace(/[^A-Za-z0-9._\-一-鿿㐀-䶿가-힯ㄱ-ㅣ぀-ヿ]/g, '-'); // 一-鿿 = CJK 基本区，㐀-䶿 = 扩展 A 区，가-힯 = 韩文音节，ㄱ-ㅣ = 韩文兼容字母，぀-ヿ = 日文假名
  base = base.replace(/-{2,}/g, '-').replace(/^[.\-]+|[.\-]+$/g, '');
  if (base.length > 80) base = base.slice(0, 80).replace(/[.\-]+$/, '');
  return base;
}

// 按扩展名归类目录：upweb/img 图片 · upweb/video 视频 · upweb/other 其他
// keepName=true 时用清洗后的原文件名；否则用随机 UUID
function makeObjectKey(filename, keepName) {
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

// 目录白名单：全部 / 图片 / 视频 / 其他
const DIR_PREFIX = { all: 'upweb/', img: 'upweb/img/', video: 'upweb/video/', other: 'upweb/other/' };

function typeOf(key) {
  const ext = (key.split('.').pop() || '').toLowerCase();
  if (IMG_EXTS.includes(ext)) return 'image';
  if (VIDEO_EXTS.includes(ext)) return 'video';
  return 'other';
}

// XML 反转义（OSS 返回的 StringToSign 里可能含 &amp; 等实体）
function xmlUnescape(s) {
  return s.replace(/&lt;/g, '<').replace(/&gt;/g, '>').replace(/&quot;/g, '"')
    .replace(/&#39;|&apos;/g, "'").replace(/&amp;/g, '&');
}

// OSS ListObjectsV2（GET Bucket），V1 签名。
// 用 x-oss-date 替代 Date 头（边缘运行时受限头会被改写，否则 SignatureDoesNotMatch）。
// 自愈机制：签名被拒时，OSS 错误 XML 里的 <StringToSign> 是服务端按实际收到的
// 请求算出的待签字符串，用它重新签名重试一次，可自动适应任何规范化差异。
async function listObjects(env, token, dir) {
  const bucket = env.OSS_BUCKET;
  const endpoint = env.OSS_ENDPOINT;
  const prefix = DIR_PREFIX[dir] || DIR_PREFIX.all;
  const params = new URLSearchParams({ 'list-type': '2', prefix: prefix, 'max-keys': '60' });
  if (token) params.set('continuation-token', token);
  const url = `https://${bucket}.${endpoint}/?${params.toString()}`;
  const date = new Date().toUTCString();
  const myStringToSign = 'GET\n\n\n\nx-oss-date:' + date + '\n/' + bucket + '/?list-type=2';
  const headers = {
    'x-oss-date': date,
    Authorization: `OSS ${env.OSS_ACCESS_KEY_ID}:${await hmacSha1Base64(env.OSS_ACCESS_KEY_SECRET, myStringToSign)}`,
  };
  let r = await fetch(url, { headers });
  let xml = await r.text();
  if (!r.ok) {
    const code = (xml.match(/<Code>([^<]+)<\/Code>/) || [])[1] || r.status;
    const ossString = (xml.match(/<StringToSign>([\s\S]*?)<\/StringToSign>/) || [])[1];
    if (code === 'SignatureDoesNotMatch' && ossString) {
      const ossStr = xmlUnescape(ossString);
      headers.Authorization = `OSS ${env.OSS_ACCESS_KEY_ID}:${await hmacSha1Base64(env.OSS_ACCESS_KEY_SECRET, ossStr)}`;
      r = await fetch(url, { headers });
      xml = await r.text();
      if (!r.ok) {
        const code2 = (xml.match(/<Code>([^<]+)<\/Code>/) || [])[1] || r.status;
        throw new Error('OSS 列表请求失败：' + code2 + '（已按 OSS 签名串重试仍失败）｜OSS期望[' + ossStr.replace(/\n/g, '⏎') + ']｜我方[' + myStringToSign.replace(/\n/g, '⏎') + ']');
      }
    } else {
      throw new Error('OSS 列表请求失败：' + code);
    }
  }
  const files = [];
  const re = /<Contents>[\s\S]*?<Key>([\s\S]*?)<\/Key>[\s\S]*?<LastModified>([\s\S]*?)<\/LastModified>[\s\S]*?<Size>(\d+)<\/Size>[\s\S]*?<\/Contents>/g;
  let m;
  while ((m = re.exec(xml)) !== null) {
    const key = xmlUnescape(m[1]);
    files.push({ key: key, time: m[2], size: parseInt(m[3], 10), type: typeOf(key), url: env.PUBLIC_URL_BASE.replace(/\/$/, '') + '/' + encodeKeyPath(key) });
  }
  const nextToken = (xml.match(/<NextContinuationToken>([^<]*)<\/NextContinuationToken>/) || [])[1] || '';
  const truncated = /<IsTruncated>true<\/IsTruncated>/.test(xml);
  return { files, nextToken, truncated };
}

async function handleList(request, env) {
  const required = ['OSS_ACCESS_KEY_ID', 'OSS_ACCESS_KEY_SECRET', 'OSS_BUCKET', 'OSS_ENDPOINT', 'PUBLIC_URL_BASE'];
  for (const k of required) {
    if (!env[k]) return jsonResponse({ error: `服务端缺少环境变量 ${k}` }, 500);
  }
  const cfgErr = authConfigError(env);
  if (cfgErr) return jsonResponse({ error: cfgErr }, 500);
  const { body, err } = await readJsonBody(request, MAX_BODY_BYTES);
  if (err) return err;
  const inputErr = badInput(body);
  if (inputErr) return jsonResponse({ error: inputErr }, 400);
  if (!(await verifyAuth(body, env))) {
    return rejectAuth();
  }
  try {
    return jsonResponse(await listObjects(env, body.token || '', String(body.dir || 'all')));
  } catch (e) {
    return jsonResponse({ error: e.message }, 502);
  }
}

// OSS DeleteObject：用 x-oss-date 替代 Date 头，自愈重试逻辑同 listObjects
// StringToSign = DELETE\n\n\n\nx-oss-date:<date>\n/<bucket>/<key>
async function deleteObject(env, key) {
  const bucket = env.OSS_BUCKET;
  const endpoint = env.OSS_ENDPOINT;
  const url = `https://${bucket}.${endpoint}/${key.split('/').map(encodeURIComponent).join('/')}`;
  const date = new Date().toUTCString();
  const myStringToSign = 'DELETE\n\n\n\nx-oss-date:' + date + '\n/' + bucket + '/' + key;
  const headers = {
    'x-oss-date': date,
    Authorization: `OSS ${env.OSS_ACCESS_KEY_ID}:${await hmacSha1Base64(env.OSS_ACCESS_KEY_SECRET, myStringToSign)}`,
  };
  let r = await fetch(url, { method: 'DELETE', headers });
  if (!r.ok && r.status !== 204) {
    const xml = await r.text();
    const code = (xml.match(/<Code>([^<]+)<\/Code>/) || [])[1] || r.status;
    const ossString = (xml.match(/<StringToSign>([\s\S]*?)<\/StringToSign>/) || [])[1];
    if (code === 'SignatureDoesNotMatch' && ossString) {
      const ossStr = xmlUnescape(ossString);
      headers.Authorization = `OSS ${env.OSS_ACCESS_KEY_ID}:${await hmacSha1Base64(env.OSS_ACCESS_KEY_SECRET, ossStr)}`;
      r = await fetch(url, { method: 'DELETE', headers });
      if (!r.ok && r.status !== 204) {
        const xml2 = await r.text();
        const code2 = (xml2.match(/<Code>([^<]+)<\/Code>/) || [])[1] || r.status;
        throw new Error('OSS 删除失败：' + code2 + '（已按 OSS 签名串重试仍失败）｜OSS期望[' + ossStr.replace(/\n/g, '⏎') + ']｜我方[' + myStringToSign.replace(/\n/g, '⏎') + ']');
      }
    } else {
      throw new Error('OSS 删除失败：' + code);
    }
  }
}

async function handleDelete(request, env) {
  const required = ['OSS_ACCESS_KEY_ID', 'OSS_ACCESS_KEY_SECRET', 'OSS_BUCKET', 'OSS_ENDPOINT'];
  for (const k of required) {
    if (!env[k]) return jsonResponse({ error: `服务端缺少环境变量 ${k}` }, 500);
  }
  const cfgErr = authConfigError(env);
  if (cfgErr) return jsonResponse({ error: cfgErr }, 500);
  const { body, err } = await readJsonBody(request, MAX_BODY_BYTES);
  if (err) return err;
  const inputErr = badInput(body);
  if (inputErr) return jsonResponse({ error: inputErr }, 400);
  if (!(await verifyAuth(body, env))) {
    return rejectAuth();
  }
  const key = String(body.key || '');
  if (!validMpKey(key)) {
    return jsonResponse({ error: '仅允许删除 upweb/ 前缀下的文件' }, 400);
  }
  try {
    await deleteObject(env, key);
    return jsonResponse({ ok: true, key });
  } catch (e) {
    return jsonResponse({ error: e.message }, 502);
  }
}

// OSS CopyObject（同桶复制，重命名前半步）
// StringToSign = PUT\n\n\n\nx-oss-copy-source:<src>\nx-oss-date:<date>\nx-oss-forbid-overwrite:true\n/<bucket>/<newKey>
// x-oss-forbid-overwrite:true —— 目标已存在则拒绝，防止改名覆盖掉别的文件
async function copyObject(env, oldKey, newKey) {
  const bucket = env.OSS_BUCKET;
  const endpoint = env.OSS_ENDPOINT;
  const url = `https://${bucket}.${endpoint}/${encodeKeyPath(newKey)}`;
  const copySource = '/' + bucket + '/' + encodeKeyPath(oldKey);
  const date = new Date().toUTCString();
  const myStringToSign = 'PUT\n\n\n\n'
    + 'x-oss-copy-source:' + copySource + '\n'
    + 'x-oss-date:' + date + '\n'
    + 'x-oss-forbid-overwrite:true\n'
    + '/' + bucket + '/' + newKey;
  const headers = {
    'x-oss-copy-source': copySource,
    'x-oss-date': date,
    'x-oss-forbid-overwrite': 'true',
    Authorization: `OSS ${env.OSS_ACCESS_KEY_ID}:${await hmacSha1Base64(env.OSS_ACCESS_KEY_SECRET, myStringToSign)}`,
  };
  let r = await fetch(url, { method: 'PUT', headers });
  if (!r.ok) {
    const xml = await r.text();
    const code = (xml.match(/<Code>([^<]+)<\/Code>/) || [])[1] || r.status;
    if (code === 'FileAlreadyExists') { const e = new Error('目标文件名已存在，请换一个名字'); e.code = 'CONFLICT'; throw e; }
    const ossString = (xml.match(/<StringToSign>([\s\S]*?)<\/StringToSign>/) || [])[1];
    if (code === 'SignatureDoesNotMatch' && ossString) {
      const ossStr = xmlUnescape(ossString);
      headers.Authorization = `OSS ${env.OSS_ACCESS_KEY_ID}:${await hmacSha1Base64(env.OSS_ACCESS_KEY_SECRET, ossStr)}`;
      r = await fetch(url, { method: 'PUT', headers });
      if (!r.ok) {
        const code2 = ((await r.text()).match(/<Code>([^<]+)<\/Code>/) || [])[1] || r.status;
        if (code2 === 'FileAlreadyExists') { const e = new Error('目标文件名已存在，请换一个名字'); e.code = 'CONFLICT'; throw e; }
        throw new Error('OSS 复制失败：' + code2);
      }
    } else {
      throw new Error('OSS 复制失败：' + code);
    }
  }
}

// 新文件名校验：与全站一致的安全字符集（中文 / 字母数字 / . _ -，保证改名后仍可被 list/delete 正常处理）
const NAME_RE = /^[A-Za-z0-9._\-一-鿿㐀-䶿가-힯ㄱ-ㅣ぀-ヿ]+$/;
// 可移动的目标目录（与前端目录标签一致）
const MOVE_DIRS = ['img', 'video', 'other'];
function validName(name) {
  return typeof name === 'string' && name.length <= 200 && NAME_RE.test(name)
    && !name.startsWith('.') && !name.includes('..');
}

// OSS 重命名 = CopyObject（同桶复制到新 key）+ DeleteObject（删旧 key）
async function handleRename(request, env) {
  const required = ['OSS_ACCESS_KEY_ID', 'OSS_ACCESS_KEY_SECRET', 'OSS_BUCKET', 'OSS_ENDPOINT', 'PUBLIC_URL_BASE'];
  for (const k of required) {
    if (!env[k]) return jsonResponse({ error: `服务端缺少环境变量 ${k}` }, 500);
  }
  const cfgErr = authConfigError(env);
  if (cfgErr) return jsonResponse({ error: cfgErr }, 500);
  const { body, err } = await readJsonBody(request, MAX_BODY_BYTES);
  if (err) return err;
  const inputErr = badInput(body);
  if (inputErr) return jsonResponse({ error: inputErr }, 400);
  if (!(await verifyAuth(body, env))) {
    return rejectAuth();
  }
  const key = String(body.key || '');
  if (!validMpKey(key)) {
    return jsonResponse({ error: '仅允许重命名 upweb/ 前缀下的文件' }, 400);
  }
  const name = String(body.name || '').trim();
  const moveDir = String(body.dir || '');
  if (!name && !moveDir) {
    return jsonResponse({ error: '缺少参数：name（改名）或 dir（移动目录）至少提供一个' }, 400);
  }
  if (name && !validName(name)) {
    return jsonResponse({ error: '文件名只允许中日韩文字、字母、数字、点、下划线、连字符（≤200 字符，不能以点开头）' }, 400);
  }
  if (moveDir && !MOVE_DIRS.includes(moveDir)) {
    return jsonResponse({ error: '目标目录非法（仅支持 img / video / other）' }, 400);
  }
  // 移动目录：保留日期路径，只替换 upweb/ 后的第一级目录；改名：替换最后一段（可叠加）
  let newKey = key;
  if (moveDir) {
    const parts = key.split('/');
    if (parts.length < 3) {
      return jsonResponse({ error: '对象路径结构非法，无法移动' }, 400);
    }
    parts[1] = moveDir;
    newKey = parts.join('/');
  }
  if (name) {
    newKey = newKey.slice(0, newKey.lastIndexOf('/') + 1) + name;
  }
  if (!validMpKey(newKey)) {
    return jsonResponse({ error: '新文件名不合法' }, 400);
  }
  if (newKey === key) {
    return jsonResponse({ ok: true, key, url: env.PUBLIC_URL_BASE.replace(/\/$/, '') + '/' + encodeKeyPath(key) });
  }
  try {
    await copyObject(env, key, newKey);
    await deleteObject(env, key);
    return jsonResponse({ ok: true, key: newKey, oldKey: key, url: env.PUBLIC_URL_BASE.replace(/\/$/, '') + '/' + encodeKeyPath(newKey) });
  } catch (e) {
    return jsonResponse({ error: e.message }, e.code === 'CONFLICT' ? 409 : 502);
  }
}

// ================= 分片上传（Multipart Upload） =================
// action=init      服务端调 InitiateMultipartUpload，返回 uploadId + key
// action=part      为单个分片签发预签名 URL（1 小时有效），浏览器直传 OSS
// action=complete  合并分片；action=abort 清理残留分片
// 每个分片即签即传、独立计时 → 慢网络总时长不设限，且支持断点续传。
// 可选环境变量 PART_SIZE_MB：分片大小，默认 10，范围 5~100。

function xmlEscape(s) {
  return String(s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;').replace(/'/g, '&#39;');
}
// key 白名单：upweb/ 前缀 + 安全字符集（字母数字 / 中文 / . _ - /），禁 .. 与引号/尖括号等可注入字符
const KEY_RE = /^upweb\/[A-Za-z0-9._\/\-一-鿿㐀-䶿가-힯ㄱ-ㅣ぀-ヿ]+$/;
function validMpKey(key) {
  return typeof key === 'string' && key.length <= 512 && KEY_RE.test(key) && !key.includes('..');
}
function encodeKeyPath(key) {
  return key.split('/').map(encodeURIComponent).join('/');
}

// 服务端签名直调 OSS（init/complete/abort），V1 Header 签名 + 签名自愈重试
async function ossRequest(env, method, key, subResource, contentType, bodyText) {
  const bucket = env.OSS_BUCKET;
  const endpoint = env.OSS_ENDPOINT;
  const url = `https://${bucket}.${endpoint}/${encodeKeyPath(key)}${subResource}`;
  const date = new Date().toUTCString();
  const canonicalizedResource = `/${bucket}/${key}${subResource}`;
  const myStringToSign = `${method}\n\n${contentType || ''}\n\nx-oss-date:${date}\n${canonicalizedResource}`;
  const headers = {
    'x-oss-date': date,
    Authorization: `OSS ${env.OSS_ACCESS_KEY_ID}:${await hmacSha1Base64(env.OSS_ACCESS_KEY_SECRET, myStringToSign)}`,
  };
  if (contentType) headers['Content-Type'] = contentType;
  let r = await fetch(url, { method, headers, body: bodyText || undefined });
  let xml = await r.text();
  if (!r.ok) {
    const code = (xml.match(/<Code>([^<]+)<\/Code>/) || [])[1] || r.status;
    const ossString = (xml.match(/<StringToSign>([\s\S]*?)<\/StringToSign>/) || [])[1];
    if (code === 'SignatureDoesNotMatch' && ossString) {
      const ossStr = xmlUnescape(ossString);
      headers.Authorization = `OSS ${env.OSS_ACCESS_KEY_ID}:${await hmacSha1Base64(env.OSS_ACCESS_KEY_SECRET, ossStr)}`;
      r = await fetch(url, { method, headers, body: bodyText || undefined });
      xml = await r.text();
      if (!r.ok) {
        const code2 = (xml.match(/<Code>([^<]+)<\/Code>/) || [])[1] || r.status;
        throw new Error(`OSS ${method} 请求失败：` + code2 + '（已按 OSS 签名串重试仍失败）｜OSS期望[' + ossStr.replace(/\n/g, '⏎') + ']｜我方[' + myStringToSign.replace(/\n/g, '⏎') + ']');
      }
    } else {
      throw new Error(`OSS ${method} 请求失败：` + code);
    }
  }
  return xml;
}

// 为单个分片签发预签名 URL（V1 URL 签名）
// StringToSign = PUT\n\n{Content-Type}\n{Expires}\n/{bucket}/{key}?partNumber={n}&uploadId={id}
async function signPartUrl(env, key, uploadId, partNumber, mime) {
  const bucket = env.OSS_BUCKET;
  const expires = Math.floor(Date.now() / 1000) + 3600;
  const stringToSign = `PUT\n\n${mime}\n${expires}\n/${bucket}/${key}?partNumber=${partNumber}&uploadId=${uploadId}`;
  const signature = await hmacSha1Base64(env.OSS_ACCESS_KEY_SECRET, stringToSign);
  return `https://${bucket}.${env.OSS_ENDPOINT}/${encodeKeyPath(key)}`
    + `?partNumber=${partNumber}&uploadId=${encodeURIComponent(uploadId)}`
    + `&OSSAccessKeyId=${encodeURIComponent(env.OSS_ACCESS_KEY_ID)}`
    + `&Expires=${expires}&Signature=${encodeURIComponent(signature)}`;
}

async function handleMultipart(request, env) {
  const required = ['OSS_ACCESS_KEY_ID', 'OSS_ACCESS_KEY_SECRET', 'OSS_BUCKET', 'OSS_ENDPOINT', 'PUBLIC_URL_BASE'];
  for (const k of required) {
    if (!env[k]) return jsonResponse({ error: `服务端缺少环境变量 ${k}` }, 500);
  }
  const cfgErr = authConfigError(env);
  if (cfgErr) return jsonResponse({ error: cfgErr }, 500);
  const { body, err } = await readJsonBody(request, 256 * 1024);
  if (err) return err;
  const inputErr = badInput(body);
  if (inputErr) return jsonResponse({ error: inputErr }, 400);
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
    if (action === 'init') {
      const size = parseInt(body.size, 10) || 0;
      if (size <= 0 || size > maxSize) {
        return jsonResponse({ error: `文件大小超限（上限 ${maxMB}MB）` }, 400);
      }
      const mime = String(body.mime || 'application/octet-stream').slice(0, 100) || 'application/octet-stream';
      const key = makeObjectKey(body.filename || 'file.bin', body.keepName === true);
      // 保留原文件名时做存在性预检（InitMultipart 不带 forbid-overwrite，合并时会静默覆盖同名对象）；
      // 需要 RAM 授权 oss:GetObject。随机 UUID key 几乎不可能碰撞，跳过预检省一次请求。
      if (body.keepName === true) {
        try {
          await ossRequest(env, 'GET', key, '?objectMeta', '', null);
          return jsonResponse({ error: `同名文件已存在：${key.split('/').pop()}（请先重命名或删除旧文件）`, code: 'CONFLICT' }, 409);
        } catch (e) {
          if (!/NoSuchKey|404|NoSuchObject/.test(e.message)) throw e;
        }
      }
      const xml = await ossRequest(env, 'POST', key, '?uploads', mime, null);
      const uploadId = (xml.match(/<UploadId>([^<]+)<\/UploadId>/) || [])[1];
      if (!uploadId) throw new Error('OSS 未返回 UploadId');
      const session = await makeMpToken(env, key, uploadId, size, partSize);
      return jsonResponse({ key, uploadId, partSize, session, dir: key.split('/').slice(0, 2).join('/') });
    }

    if (action === 'part') {
      const key = String(body.key || '');
      const uploadId = String(body.uploadId || '');
      const partNumber = parseInt(body.partNumber, 10);
      if (!validMpKey(key) || !uploadId) return jsonResponse({ error: '参数非法' }, 400);
      if (!Number.isInteger(partNumber) || partNumber < 1 || partNumber > 10000) {
        return jsonResponse({ error: 'partNumber 须在 1~10000 之间' }, 400);
      }
      const mp = await mpSession(body, key, uploadId, env);
      if (!mp) return rejectSession();
      if (partNumber > mp.m) {
        return jsonResponse({ error: `分片号超出本会话上限（最多 ${mp.m} 片）`, code: 'BAD_SESSION' }, 400);
      }
      const mime = String(body.mime || 'application/octet-stream').slice(0, 100) || 'application/octet-stream';
      return jsonResponse({ url: await signPartUrl(env, key, uploadId, partNumber, mime), expiresIn: 3600 });
    }

    if (action === 'complete') {
      const key = String(body.key || '');
      const uploadId = String(body.uploadId || '');
      const parts = Array.isArray(body.parts) ? body.parts : [];
      if (!validMpKey(key) || !uploadId || parts.length === 0 || parts.length > 10000) {
        return jsonResponse({ error: '参数非法' }, 400);
      }
      const mp = await mpSession(body, key, uploadId, env);
      if (!mp) return rejectSession();
      if (parts.length > mp.m) {
        return jsonResponse({ error: `分片数超出本会话上限（最多 ${mp.m} 片）`, code: 'BAD_SESSION' }, 400);
      }
      // ListParts 逐片核验：分片号 + ETag + 每片字节数必须与 init 声明完全吻合。
      // 预签名 URL 有效期内可重复 PUT 同号分片覆盖，逐片精确比对封死
      // 「检查后偷换大分片」的 TOCTOU 绕过路径。
      if (typeof mp.z !== 'number' || mp.z <= 0) {
        // 旧版会话令牌没有 partSize 字段：按会话失效处理，前端会自动重新 init
        return rejectSession();
      }
      const expectedSizeOf = n => (n < mp.m ? mp.z : mp.s - (mp.m - 1) * mp.z);
      const actual = new Map(); // partNumber -> { etag, size }
      let marker = 0;
      for (let guard = 0; guard < 20; guard++) {
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
      await ossRequest(env, 'POST', key, `?uploadId=${encodeURIComponent(uploadId)}`, 'application/xml', xmlBody);
      return jsonResponse({ ok: true, key, url: `${env.PUBLIC_URL_BASE.replace(/\/$/, '')}/${encodeKeyPath(key)}`, dir: key.split('/').slice(0, 2).join('/') });
    }

    if (action === 'abort') {
      const key = String(body.key || '');
      const uploadId = String(body.uploadId || '');
      if (!validMpKey(key) || !uploadId) return jsonResponse({ error: '参数非法' }, 400);
      const mp = await mpSession(body, key, uploadId, env);
      if (!mp) return rejectSession();
      await ossRequest(env, 'DELETE', key, `?uploadId=${encodeURIComponent(uploadId)}`, '', null);
      return jsonResponse({ ok: true });
    }

    return jsonResponse({ error: '未知 action（支持 init/part/complete/abort）' }, 400);
  } catch (e) {
    return jsonResponse({ error: e.message }, 502);
  }
}

async function handleSign(request, env) {
  const required = ['OSS_ACCESS_KEY_ID', 'OSS_ACCESS_KEY_SECRET', 'OSS_BUCKET', 'OSS_ENDPOINT', 'PUBLIC_URL_BASE'];
  for (const k of required) {
    if (!env[k]) return jsonResponse({ error: `服务端缺少环境变量 ${k}` }, 500);
  }
  const cfgErr = authConfigError(env);
  if (cfgErr) return jsonResponse({ error: cfgErr }, 500);
  const { body, err } = await readJsonBody(request, MAX_BODY_BYTES);
  if (err) return err;
  const inputErr = badInput(body);
  if (inputErr) return jsonResponse({ error: inputErr }, 400);

  const maxMB = parseInt(env.MAX_SIZE_MB, 10) || 100;
  const maxSize = maxMB * 1024 * 1024;

  // 密码预检：前端登录门禁专用；仅密码通过才签发 7 天令牌，持令牌预检不续签
  if (body.check === true) {
    const authBy = await verifyAuth(body, env);
    if (!authBy) {
      return rejectAuth();
    }
    const resp = { ok: true, needPassword: !!env.UPLOAD_PASSWORD, maxMB };
    if (authBy === 'pwd' && env.UPLOAD_PASSWORD) resp.token = await makeAuthToken(env);
    return jsonResponse(resp);
  }

  if (!(await verifyAuth(body, env))) {
    return rejectAuth();
  }

  const size = parseInt(body.size, 10) || 0;
  if (size <= 0 || size > maxSize) {
    return jsonResponse({ error: `文件大小超限（上限 ${maxMB}MB）` }, 400);
  }

  const objectKey = makeObjectKey(body.filename || 'file.bin', body.keepName === true);
  const policy = btoa(JSON.stringify({
    expiration: new Date(Date.now() + 10 * 60 * 1000).toISOString(),
    conditions: [
      { bucket: env.OSS_BUCKET },
      ['content-length-range', 1, maxSize],
      ['eq', '$key', objectKey],
      ['eq', '$x-oss-forbid-overwrite', 'true'],
    ],
  }));
  const signature = await hmacSha1Base64(env.OSS_ACCESS_KEY_SECRET, policy);

  return jsonResponse({
    host: `https://${env.OSS_BUCKET}.${env.OSS_ENDPOINT}`,
    fields: {
      key: objectKey,
      policy,
      OSSAccessKeyId: env.OSS_ACCESS_KEY_ID,
      success_action_status: '200',
      signature,
      'x-oss-forbid-overwrite': 'true',
    },
    url: `${env.PUBLIC_URL_BASE.replace(/\/$/, '')}/${encodeKeyPath(objectKey)}`,
    dir: objectKey.split('/').slice(0, 2).join('/'),
  });
}

// ================= PicGo / 第三方客户端兼容上传（POST /api/upload） =================
// 接收 multipart/form-data 文件，服务端签名后直接 PutObject 写入 OSS，返回 PicGo 兼容 JSON。
// 鉴权（任一）：Authorization: Bearer <密码或令牌> / x-yunwo-password 头 / 表单 password 或 auth 字段。
// PicGo 配置：API 地址 https://你的域名/api/upload，POST 参数名 file，返回 JSON 路径 data.url，
//   自定义请求头 {"Authorization":"Bearer 你的上传密码"}。
// 默认保留原文件名（表单 keepname=0/false 关闭）；同名冲突返回 409，绝不静默覆盖。
// 注意：文件内容会读入 Worker 内存，MAX_SIZE_MB 勿超过平台请求体限制。

function picgoOk(url, key, name, size) {
  return jsonResponse({ success: true, code: 200, message: 'ok', result: [url], data: { url, key, name, size } });
}
function picgoErr(message, status) {
  return jsonResponse({ success: false, code: status, message, error: message }, status);
}

// 服务端签名 PutObject（V1 Header 签名）+ 签名自愈重试一次；x-oss-forbid-overwrite 写死
async function putObject(env, key, bytes, contentType) {
  const bucket = env.OSS_BUCKET;
  const endpoint = env.OSS_ENDPOINT;
  const url = `https://${bucket}.${endpoint}/${encodeKeyPath(key)}`;
  const date = new Date().toUTCString();
  // x-oss- 头按名称字典序进入待签串：x-oss-date < x-oss-forbid-overwrite
  const myStringToSign = `PUT\n\n${contentType}\n\nx-oss-date:${date}\nx-oss-forbid-overwrite:true\n/${bucket}/${key}`;
  const headers = {
    'x-oss-date': date,
    'x-oss-forbid-overwrite': 'true',
    'Content-Type': contentType,
    Authorization: `OSS ${env.OSS_ACCESS_KEY_ID}:${await hmacSha1Base64(env.OSS_ACCESS_KEY_SECRET, myStringToSign)}`,
  };
  let r = await fetch(url, { method: 'PUT', headers, body: bytes });
  let xml = await r.text();
  if (!r.ok) {
    const code = (xml.match(/<Code>([^<]+)<\/Code>/) || [])[1] || r.status;
    const ossString = (xml.match(/<StringToSign>([\s\S]*?)<\/StringToSign>/) || [])[1];
    if (code === 'SignatureDoesNotMatch' && ossString) {
      const ossStr = xmlUnescape(ossString);
      headers.Authorization = `OSS ${env.OSS_ACCESS_KEY_ID}:${await hmacSha1Base64(env.OSS_ACCESS_KEY_SECRET, ossStr)}`;
      r = await fetch(url, { method: 'PUT', headers, body: bytes });
      xml = await r.text();
      if (!r.ok) {
        const code2 = (xml.match(/<Code>([^<]+)<\/Code>/) || [])[1] || r.status;
        throw new Error(`OSS PUT 请求失败：` + code2);
      }
    } else if (code === 'FileAlreadyExists') {
      const err = new Error('同名文件已存在，请先重命名或删除旧文件');
      err.code = 'CONFLICT';
      throw err;
    } else {
      throw new Error(`OSS PUT 请求失败：` + code);
    }
  }
}

async function handleUpload(request, env) {
  const required = ['OSS_ACCESS_KEY_ID', 'OSS_ACCESS_KEY_SECRET', 'OSS_BUCKET', 'OSS_ENDPOINT', 'PUBLIC_URL_BASE'];
  for (const k of required) {
    if (!env[k]) return picgoErr(`服务端缺少环境变量 ${k}`, 500);
  }
  const cfgErr = authConfigError(env);
  if (cfgErr) return picgoErr(cfgErr, 500);

  const maxMB = parseInt(env.MAX_SIZE_MB, 10) || 100;
  const maxSize = maxMB * 1024 * 1024;
  // Content-Length 快路径：超限直接 413（multipart 开销放宽 2MB）；头不可信时由 file.size 兜底
  const cl = parseInt(request.headers.get('Content-Length') || '0', 10);
  if (cl > maxSize + 2 * 1024 * 1024) {
    return picgoErr(`文件大小超限（上限 ${maxMB}MB）`, 413);
  }
  const ct = request.headers.get('Content-Type') || '';
  if (!ct.toLowerCase().startsWith('multipart/form-data')) {
    return picgoErr('Content-Type 必须是 multipart/form-data', 400);
  }
  let form;
  try {
    form = await request.formData();
  } catch {
    return picgoErr('表单解析失败', 400);
  }
  // 取文件：优先 file 字段（PicGo 默认），否则取第一个文件字段
  let file = form.get('file');
  if (!(file instanceof File)) {
    for (const v of form.values()) {
      if (v instanceof File) { file = v; break; }
    }
  }
  if (!(file instanceof File) || file.size <= 0) {
    return picgoErr('未收到文件（表单中需要一个文件字段，推荐命名为 file）', 400);
  }
  if (file.size > maxSize) {
    return picgoErr(`文件大小超限（上限 ${maxMB}MB）`, 413);
  }

  // 鉴权：请求头优先（Bearer 可为密码或令牌），其次表单字段
  const creds = { password: '', auth: '' };
  const m = (request.headers.get('Authorization') || '').match(/^Bearer\s+(.+)$/i);
  if (m) { creds.password = m[1]; creds.auth = m[1]; }
  const hdrPwd = request.headers.get('x-yunwo-password');
  if (hdrPwd) creds.password = hdrPwd;
  const fPwd = form.get('password');
  const fAuth = form.get('auth');
  if (typeof fPwd === 'string' && fPwd) creds.password = fPwd;
  if (typeof fAuth === 'string' && fAuth) creds.auth = fAuth;
  if (creds.password.length > 128 || creds.auth.length > 2048) {
    return picgoErr('鉴权参数非法', 400);
  }
  if (!(await verifyAuth(creds, env))) {
    await new Promise(r => setTimeout(r, 400));
    return picgoErr('上传密码错误或会话已过期', 401);
  }

  const kn = String(form.get('keepname') || '').toLowerCase();
  const keepName = kn !== '0' && kn !== 'false';
  const key = makeObjectKey(file.name || 'file.bin', keepName);

  try {
    const bytes = await file.arrayBuffer();
    const mime = (file.type || 'application/octet-stream').slice(0, 100);
    await putObject(env, key, bytes, mime);
    const url = `${env.PUBLIC_URL_BASE.replace(/\/$/, '')}/${encodeKeyPath(key)}`;
    return picgoOk(url, key, file.name, file.size);
  } catch (e) {
    if (e.code === 'CONFLICT') return picgoErr(e.message, 409);
    return picgoErr(e.message, 502);
  }
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    if (request.method === 'OPTIONS') return new Response(null, { headers: CORS });
    if (url.pathname === '/api/sign' && request.method === 'POST') return handleSign(request, env);
    if (url.pathname === '/api/list' && request.method === 'POST') return handleList(request, env);
    if (url.pathname === '/api/delete' && request.method === 'POST') return handleDelete(request, env);
    if (url.pathname === '/api/rename' && request.method === 'POST') return handleRename(request, env);
    if (url.pathname === '/api/multipart' && request.method === 'POST') return handleMultipart(request, env);
    if (url.pathname === '/api/upload' && request.method === 'POST') return handleUpload(request, env);
    return jsonResponse({ error: 'Not Found. 接口：POST /api/sign、POST /api/list、POST /api/delete、POST /api/rename、POST /api/multipart、POST /api/upload。' }, 404);
  },
};
