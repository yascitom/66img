// ============================================================
// OSS 文件列表函数 —— EdgeOne Pages Functions / Cloudflare Pages Functions 通用版
// 路由：POST /api/list
// 原理：服务端用 AccessKey 签名调用 OSS ListObjectsV2，返回文件列表。
//       仅允许列出 upweb/ 前缀，密钥不出服务端。
// 请求体：{ auth 或 password, token?, dir? }   auth 为登录令牌，token 为分页游标，dir ∈ all/img/video/other
// 返回：{ files:[{key,size,time,type,url}], nextToken, truncated }
// 环境变量与 sign.js 相同。
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

// XML 反转义（OSS 返回的 StringToSign 里可能含 &amp; 等实体）
function xmlUnescape(s) {
  return s
    .replace(/&lt;/g, '<')
    .replace(/&gt;/g, '>')
    .replace(/&quot;/g, '"')
    .replace(/&#39;|&apos;/g, "'")
    .replace(/&amp;/g, '&');
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
// 鉴权配置（fail-closed）与 HMAC 会话令牌（与 sign.js 相同实现）
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

// payload 可能含中日韩 key，JSON 解码须走 UTF-8 字节（atob 只认 Latin-1）；与 sign.js 相同实现
function b64urlJsonDecode(s) {
  const bin = atob(s.replace(/-/g, '+').replace(/_/g, '/'));
  return JSON.parse(new TextDecoder().decode(Uint8Array.from(bin, c => c.charCodeAt(0))));
}

async function hmacSha256B64url(secret, message) {
  const enc = new TextEncoder();
  const key = await crypto.subtle.importKey('raw', enc.encode(secret), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  const sig = await crypto.subtle.sign('HMAC', key, enc.encode(message));
  return b64urlEncode(String.fromCharCode(...new Uint8Array(sig)));
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
const MAX_BODY_BYTES = 8192;
function badInput(body) {
  if (!body || typeof body !== 'object') return '请求体必须是 JSON 对象';
  const limits = { password: 128, auth: 2048, token: 2048, dir: 16 };
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

// 对象键逐段编码（保留 / 分隔符），用于拼接对外访问 URL
function encodeKeyPath(key) {
  return key.split('/').map(encodeURIComponent).join('/');
}

// 目录白名单：前端可选 全部 / 图片 / 视频 / 其他
const DIR_PREFIX = {
  all: 'upweb/',
  img: 'upweb/img/',
  video: 'upweb/video/',
  other: 'upweb/other/',
};

const IMG_EXTS = ['jpg', 'jpeg', 'png', 'gif', 'webp', 'svg', 'avif', 'bmp', 'ico', 'tiff'];
const VIDEO_EXTS = ['mp4', 'webm', 'mov', 'mkv', 'm4v', 'avi', 'flv', 'ts'];

function typeOf(key) {
  const ext = (key.split('.').pop() || '').toLowerCase();
  if (IMG_EXTS.includes(ext)) return 'image';
  if (VIDEO_EXTS.includes(ext)) return 'video';
  return 'other';
}

// ------------------------------------------------------------
// 带超时与瞬时故障重试的 fetch（与 multipart.js 相同实现）：
// 边缘运行时到 OSS 的子请求偶发 net_exception_timeout 等网络抖动，
// 单次抖动不应直接表现为「列表加载失败」。仅网络层错误重试；
// OSS 已应答的业务错误（4xx 等）不在此层处理，交由下方错误分支判断。
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

// OSS ListObjectsV2（GET Bucket），V1 签名。
// 使用 x-oss-date 替代 Date 头（边缘运行时会改写 Date），
// StringToSign = GET\n\n\n\nx-oss-date:<date>\n/<bucket>/?list-type=2
//
// 自愈机制：若签名被 OSS 拒绝（SignatureDoesNotMatch），错误 XML 中会带
// <StringToSign> —— 那是 OSS 服务端按实际收到的请求计算出的待签字符串。
// 用它重新签名并重试一次，可自动适应任何规范化差异（例如边缘运行时改写/新增请求头）。
async function listObjects(env, token, dir) {
  const bucket = env.OSS_BUCKET;
  const endpoint = env.OSS_ENDPOINT;
  const prefix = DIR_PREFIX[dir] || DIR_PREFIX.all;

  const params = new URLSearchParams({
    'list-type': '2',
    prefix: prefix,
    'max-keys': '60',
  });
  if (token) params.set('continuation-token', token);
  const url = `https://${bucket}.${endpoint}/?${params.toString()}`;

  const date = new Date().toUTCString();
  const myStringToSign = 'GET\n\n\n\nx-oss-date:' + date + '\n/' + bucket + '/?list-type=2';
  const headers = {
    'x-oss-date': date,
    Authorization: `OSS ${env.OSS_ACCESS_KEY_ID}:${await hmacSha1Base64(env.OSS_ACCESS_KEY_SECRET, myStringToSign)}`,
  };

  let r = await fetchWithRetry(url, { headers });
  let xml = await r.text();

  if (!r.ok) {
    const code = (xml.match(/<Code>([^<]+)<\/Code>/) || [])[1] || r.status;
    const ossString = (xml.match(/<StringToSign>([\s\S]*?)<\/StringToSign>/) || [])[1];

    // 自愈重试：用 OSS 服务端算出的 StringToSign 重新签名
    if (code === 'SignatureDoesNotMatch' && ossString) {
      const ossStr = xmlUnescape(ossString);
      headers.Authorization = `OSS ${env.OSS_ACCESS_KEY_ID}:${await hmacSha1Base64(env.OSS_ACCESS_KEY_SECRET, ossStr)}`;
      r = await fetchWithRetry(url, { headers });
      xml = await r.text();
      if (!r.ok) {
        const code2 = (xml.match(/<Code>([^<]+)<\/Code>/) || [])[1] || r.status;
        // 签名排障细节（双方 StringToSign）只进平台日志，不进响应体
        console.error('OSS 列表重签仍失败：', code2, '｜OSS期望[', ossStr, ']｜我方[', myStringToSign, ']');
        throw new Error('OSS 列表请求失败：' + code2);
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
    files.push({
      key: key,
      time: m[2],
      size: parseInt(m[3], 10),
      type: typeOf(key),
      url: env.PUBLIC_URL_BASE.replace(/\/$/, '') + '/' + encodeKeyPath(key),
    });
  }

  const nextToken = (xml.match(/<NextContinuationToken>([^<]*)<\/NextContinuationToken>/) || [])[1] || '';
  const truncated = /<IsTruncated>true<\/IsTruncated>/.test(xml);

  return { files, nextToken, truncated };
}

async function handle(request, env) {
  if (request.method !== 'POST') {
    return jsonResponse({ error: 'Method Not Allowed' }, 405);
  }

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
    const result = await listObjects(env, body.token || '', String(body.dir || 'all'));
    return jsonResponse(result);
  } catch (e) {
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
