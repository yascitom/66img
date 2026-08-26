// ============================================================
// PicGo / 第三方客户端兼容上传接口 —— EdgeOne Pages Functions / Cloudflare Pages Functions 通用版
// 路由：POST /api/upload
// 原理：接收 multipart/form-data 文件，服务端签名后直接 PutObject 写入 OSS，
//       返回 PicGo 兼容 JSON。AccessKey 不出服务端。
// PicGo 配置（PicGo → 图床设置 → 自定义 Web 图床）：
//   API 地址:  https://你的域名/api/upload
//   POST 参数名: file
//   自定义请求头: {"Authorization":"Bearer 你的上传密码"}
//   返回 JSON 路径: data.url
// 鉴权（任一即可）：
//   请求头 Authorization: Bearer <上传密码或 7 天登录令牌>
//   请求头 x-yunwo-password: <上传密码>
//   表单字段 password=<上传密码> 或 auth=<7 天登录令牌>
// 环境变量：与 sign.js 完全相同（OSS_* / PUBLIC_URL_BASE / UPLOAD_PASSWORD / MAX_SIZE_MB）
// 注意：本接口会把文件内容读入边缘函数内存，MAX_SIZE_MB 建议不超过平台请求体限制
// ============================================================

const JSON_HEADERS = { 'Content-Type': 'application/json; charset=utf-8' };

function jsonResponse(obj, status = 200) {
  return new Response(JSON.stringify(obj), { status, headers: JSON_HEADERS });
}

// PicGo 期望 success:true + 可配置路径取 URL；同时给 result/data 两种常见形状
function picgoOk(url, key, name, size) {
  return jsonResponse({ success: true, code: 200, message: 'ok', result: [url], data: { url, key, name, size } });
}
function picgoErr(message, status) {
  return jsonResponse({ success: false, code: status, message, error: message }, status);
}

// HMAC-SHA1 → Base64（Web Crypto，三个平台的运行时都支持）
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
  return s.replace(/&quot;/g, '"').replace(/&#39;|&apos;/g, "'").replace(/&lt;/g, '<').replace(/&gt;/g, '>').replace(/&amp;/g, '&');
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
  return picgoErr('上传密码错误或会话已过期', 401);
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

// 校验令牌签名与有效期，返回 payload 或 null
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

// 令牌派生密钥：HMAC(SK, 版本标识 | Bucket | 密码哈希)——改密码即作废全部令牌
async function tokenKey(env) {
  const fp = await sha256Hex(env.UPLOAD_PASSWORD || '');
  return hmacSha256B64url(env.OSS_ACCESS_KEY_SECRET, 'yunwo-auth-v1|' + env.OSS_BUCKET + '|' + fp);
}

// 统一鉴权：creds.password 为密码、creds.auth 为 7 天令牌；返回 'pwd'/'token'/null
async function verifyAuth(creds, env) {
  if (await pwdOk(creds.password, env.UPLOAD_PASSWORD)) return 'pwd';
  const p = await readToken(creds.auth, await tokenKey(env));
  return (p && p.t === 'auth') ? 'token' : null;
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

// 按扩展名归类目录，生成对象键（与 sign.js 同一套规则）
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

// 对象键逐段编码（保留 / 分隔符），用于拼接 URL 路径（中文文件名必须编码）
function encodeKeyPath(key) {
  return key.split('/').map(encodeURIComponent).join('/');
}

// ------------------------------------------------------------
// 服务端签名 PutObject（V1 Header 签名）+ 签名自愈：
// 若 OSS 返回 SignatureDoesNotMatch，用其错误 XML 中 <StringToSign> 重签重试一次。
// x-oss-forbid-overwrite:true 写死：同名对象绝不静默覆盖（冲突返回 409）。
// ------------------------------------------------------------
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

async function handle(request, env) {
  if (request.method !== 'POST') {
    return picgoErr('Method Not Allowed', 405);
  }

  const required = ['OSS_ACCESS_KEY_ID', 'OSS_ACCESS_KEY_SECRET', 'OSS_BUCKET', 'OSS_ENDPOINT', 'PUBLIC_URL_BASE'];
  for (const k of required) {
    if (!env[k]) return picgoErr(`服务端缺少环境变量 ${k}`, 500);
  }

  // 鉴权配置检查（fail-closed）：密码未配 / 弱密码 → 拒绝服务
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
  const bearer = request.headers.get('Authorization') || '';
  const m = bearer.match(/^Bearer\s+(.+)$/i);
  if (m) { creds.password = m[1]; creds.auth = m[1]; } // 两种都试：verifyAuth 先按密码、再按令牌
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
    return rejectAuth();
  }

  // 默认保留原文件名（PicGo 场景需要可读的链接名）；表单 keepname=0/false 可关闭
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

// EdgeOne Pages Functions / Cloudflare Pages Functions 入口
export async function onRequestPost(context) {
  return handle(context.request, context.env);
}
export async function onRequest(context) {
  return handle(context.request, context.env);
}
