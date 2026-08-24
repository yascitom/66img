// ============================================================
// OSS 文件删除函数 —— EdgeOne Pages Functions / Cloudflare Pages Functions 通用版
// 路由：POST /api/delete
// 原理：服务端用 AccessKey 签名调用 OSS DeleteObject，仅允许删除 upweb/ 前缀。
// 请求体：{ auth 或 password, key }
// 环境变量与 sign.js 相同。RAM 子账号需授予 oss:DeleteObject 权限。
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

// OSS DeleteObject。使用 x-oss-date 替代 Date 头（边缘运行时会改写 Date），
// StringToSign = DELETE\n\n\n\nx-oss-date:<date>\n/<bucket>/<key>
//
// 自愈机制同 list.js：签名被拒时用 OSS 返回的 <StringToSign> 重签重试一次。
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
        throw new Error(
          'OSS 删除失败：' + code2 +
          '（已按 OSS 签名串重试仍失败）｜OSS期望[' + ossStr.replace(/\n/g, '⏎') +
          ']｜我方[' + myStringToSign.replace(/\n/g, '⏎') + ']'
        );
      }
    } else {
      throw new Error('OSS 删除失败：' + code);
    }
  }
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
    const p = JSON.parse(b64urlDecode(body));
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
  const limits = { password: 128, auth: 2048, key: 512 };
  for (const k of Object.keys(limits)) {
    if (typeof body[k] === 'string' && body[k].length > limits[k]) return '参数非法';
  }
  return '';
}
function bodyTooLarge(request) {
  const cl = parseInt(request.headers.get('Content-Length') || '0', 10);
  return cl > MAX_BODY_BYTES;
}

// key 白名单：upweb/ 前缀 + 安全字符集（字母数字 . _ - /），禁 .. 与可注入字符
const KEY_RE = /^upweb\/[A-Za-z0-9._\/-]+$/;
function validKey(key) {
  return typeof key === 'string' && key.length <= 512 && KEY_RE.test(key) && !key.includes('..');
}

async function handle(request, env) {
  if (request.method !== 'POST') {
    return jsonResponse({ error: 'Method Not Allowed' }, 405);
  }

  const required = ['OSS_ACCESS_KEY_ID', 'OSS_ACCESS_KEY_SECRET', 'OSS_BUCKET', 'OSS_ENDPOINT'];
  for (const k of required) {
    if (!env[k]) return jsonResponse({ error: `服务端缺少环境变量 ${k}` }, 500);
  }

  const cfgErr = authConfigError(env);
  if (cfgErr) return jsonResponse({ error: cfgErr }, 500);

  if (bodyTooLarge(request)) return jsonResponse({ error: '请求体过大' }, 413);

  let body;
  try {
    body = await request.json();
  } catch {
    return jsonResponse({ error: '请求体必须是 JSON' }, 400);
  }
  const inputErr = badInput(body);
  if (inputErr) return jsonResponse({ error: inputErr }, 400);

  if (!(await verifyAuth(body, env))) {
    return rejectAuth();
  }

  const key = String(body.key || '');
  if (!validKey(key)) {
    return jsonResponse({ error: '仅允许删除 upweb/ 前缀下的文件' }, 400);
  }

  try {
    await deleteObject(env, key);
    return jsonResponse({ ok: true, key });
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
