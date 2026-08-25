// ============================================================
// OSS 文件重命名函数 —— EdgeOne Pages Functions / Cloudflare Pages Functions 通用版
// 路由：POST /api/rename
// 原理：OSS 没有原生 rename，改名 = CopyObject（同桶复制到新 key）+ DeleteObject（删旧 key）。
// 请求体：{ auth 或 password, key, name }（name 为新文件名，不含目录）
// 环境变量与 sign.js 相同，另需 PUBLIC_URL_BASE（返回新直链）。
// RAM 子账号需授予 oss:GetObject（复制源）、oss:PutObject（写入新键）、oss:DeleteObject 权限。
// 安全：新旧 key 均强制 upweb/ 前缀白名单；禁止覆盖已存在的同名文件；全程密钥不出服务端。
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

function encodeKeyPath(key) {
  return key.split('/').map(encodeURIComponent).join('/');
}

// OSS CopyObject（同桶复制，改名前半步）
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
    if (code === 'FileAlreadyExists') {
      const err = new Error('目标文件名已存在，请换一个名字');
      err.code = 'CONFLICT';
      throw err;
    }
    const ossString = (xml.match(/<StringToSign>([\s\S]*?)<\/StringToSign>/) || [])[1];
    // 自愈机制同 list.js：签名被拒时用 OSS 返回的 <StringToSign> 重签重试一次
    if (code === 'SignatureDoesNotMatch' && ossString) {
      const ossStr = xmlUnescape(ossString);
      headers.Authorization = `OSS ${env.OSS_ACCESS_KEY_ID}:${await hmacSha1Base64(env.OSS_ACCESS_KEY_SECRET, ossStr)}`;
      r = await fetch(url, { method: 'PUT', headers });
      if (!r.ok) {
        const xml2 = await r.text();
        const code2 = (xml2.match(/<Code>([^<]+)<\/Code>/) || [])[1] || r.status;
        if (code2 === 'FileAlreadyExists') {
          const err = new Error('目标文件名已存在，请换一个名字');
          err.code = 'CONFLICT';
          throw err;
        }
        throw new Error('OSS 复制失败：' + code2);
      }
    } else {
      throw new Error('OSS 复制失败：' + code);
    }
  }
}

// OSS DeleteObject（改名后半步：删除旧 key）。自愈重试同 delete.js
async function deleteObject(env, key) {
  const bucket = env.OSS_BUCKET;
  const endpoint = env.OSS_ENDPOINT;
  const url = `https://${bucket}.${endpoint}/${encodeKeyPath(key)}`;

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
        const code2 = ((await r.text()).match(/<Code>([^<]+)<\/Code>/) || [])[1] || r.status;
        throw new Error('OSS 删除旧文件失败：' + code2);
      }
    } else {
      throw new Error('OSS 删除旧文件失败：' + code);
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
  const limits = { password: 128, auth: 2048, key: 512, name: 256, dir: 16 };
  for (const k of Object.keys(limits)) {
    if (typeof body[k] === 'string' && body[k].length > limits[k]) return '参数非法';
  }
  return '';
}
// 读取并校验请求体：Content-Length 超限走快路径直接 413；头缺失/不可信时按实际读入字节数兜底
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

// key 白名单：upweb/ 前缀 + 安全字符集（字母数字 / 中文 / . _ - /），禁 .. 与可注入字符
const KEY_RE = /^upweb\/[A-Za-z0-9._\/\-一-鿿㐀-䶿]+$/;
function validKey(key) {
  return typeof key === 'string' && key.length <= 512 && KEY_RE.test(key) && !key.includes('..');
}

// 新文件名校验：与全站一致的安全字符集（中文 / 字母数字 / . _ -，保证改名后仍可被 list/delete 正常处理）；
// 不允许以 . 开头、不允许纯点、不允许带目录分隔符
const NAME_RE = /^[A-Za-z0-9._\-一-鿿㐀-䶿]+$/;
function validName(name) {
  return typeof name === 'string' && name.length <= 200 && NAME_RE.test(name)
    && !name.startsWith('.') && !name.includes('..');
}

// 可移动的目标目录（与前端目录标签一致）
const MOVE_DIRS = ['img', 'video', 'other'];

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

  const key = String(body.key || '');
  if (!validKey(key)) {
    return jsonResponse({ error: '仅允许重命名 upweb/ 前缀下的文件' }, 400);
  }

  const name = String(body.name || '').trim();
  const moveDir = String(body.dir || '');
  if (!name && !moveDir) {
    return jsonResponse({ error: '缺少参数：name（改名）或 dir（移动目录）至少提供一个' }, 400);
  }
  if (name && !validName(name)) {
    return jsonResponse({ error: '文件名只允许中文、字母、数字、点、下划线、连字符（≤200 字符，不能以点开头）' }, 400);
  }
  if (moveDir && !MOVE_DIRS.includes(moveDir)) {
    return jsonResponse({ error: '目标目录非法（仅支持 img / video / other）' }, 400);
  }

  // 移动目录：保留日期路径，只替换 upweb/ 后的第一级目录（upweb/img/20260824/x.jpg → upweb/video/20260824/x.jpg）
  let newKey = key;
  if (moveDir) {
    const parts = key.split('/');
    if (parts.length < 3) {
      return jsonResponse({ error: '对象路径结构非法，无法移动' }, 400);
    }
    parts[1] = moveDir;
    newKey = parts.join('/');
  }
  // 改名：替换最后一段文件名（可与移动目录叠加）
  if (name) {
    newKey = newKey.slice(0, newKey.lastIndexOf('/') + 1) + name;
  }
  if (!validKey(newKey)) {
    return jsonResponse({ error: '新文件名不合法' }, 400);
  }
  if (newKey === key) {
    return jsonResponse({ ok: true, key, url: env.PUBLIC_URL_BASE.replace(/\/$/, '') + '/' + encodeKeyPath(key) });
  }

  try {
    await copyObject(env, key, newKey);
    await deleteObject(env, key);
    return jsonResponse({
      ok: true,
      key: newKey,
      oldKey: key,
      url: env.PUBLIC_URL_BASE.replace(/\/$/, '') + '/' + encodeKeyPath(newKey),
    });
  } catch (e) {
    return jsonResponse({ error: e.message }, e.code === 'CONFLICT' ? 409 : 502);
  }
}

// EdgeOne Pages Functions / Cloudflare Pages Functions 入口
export async function onRequestPost(context) {
  return handle(context.request, context.env);
}
export async function onRequest(context) {
  return handle(context.request, context.env);
}
