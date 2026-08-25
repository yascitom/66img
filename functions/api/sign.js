// ============================================================
// OSS 直传签名函数 —— EdgeOne Pages Functions / Cloudflare Pages Functions 通用版
// 路由：POST /api/sign
// 原理：生成 OSS PostObject 的 Policy + 签名，浏览器拿到后直传 OSS，
//       本函数不接触文件内容，每次上传仅调用 1 次。
// 目录规则（按扩展名自动归类）：
//   upweb/img/    图片：jpg jpeg png gif webp svg avif bmp ico tiff
//   upweb/video/  视频：mp4 webm mov mkv m4v avi flv ts
//   upweb/other/  其他一切（压缩包、文档、音频…）
// 环境变量（在平台控制台配置，切勿写进代码仓库）：
//   OSS_ACCESS_KEY_ID      阿里云 OSS AccessKeyId（建议用仅授权该桶的 RAM 子账号）
//   OSS_ACCESS_KEY_SECRET  对应的 AccessKeySecret
//   OSS_BUCKET             Bucket 名称，如 my-img
//   OSS_ENDPOINT           Bucket 地域节点，如 oss-cn-hongkong.aliyuncs.com
//   PUBLIC_URL_BASE        文件访问域名（CF 免流域名），如 https://img.example.com
//   UPLOAD_PASSWORD        上传密码（必填，≥10 位）；未配置或太短将拒绝服务
//   ALLOW_ANONYMOUS_UPLOAD （可选）显式设为 true 才允许免密码公开上传（不推荐）
//   MAX_SIZE_MB            （可选）单文件上限，默认 100（视频建议放大）
// ============================================================

const JSON_HEADERS = { 'Content-Type': 'application/json; charset=utf-8' };

function jsonResponse(obj, status = 200) {
  return new Response(JSON.stringify(obj), { status, headers: JSON_HEADERS });
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
// 鉴权配置（fail-closed）与 HMAC 会话令牌
// ============================================================
// 配置检查：未设密码且未显式允许匿名 → 拒绝服务；密码 < 10 位 → 拒绝服务。
// 返回 '' 表示配置可用，否则返回给前端的错误说明。
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

// base64url 编解码（payload 均为 ASCII，可直接 btoa/atob）
function b64urlEncode(s) { return btoa(s).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, ''); }
function b64urlDecode(s) { return atob(s.replace(/-/g, '+').replace(/_/g, '/')); }

// HMAC-SHA256 → base64url（Web Crypto）
async function hmacSha256B64url(secret, message) {
  const enc = new TextEncoder();
  const key = await crypto.subtle.importKey('raw', enc.encode(secret), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  const sig = await crypto.subtle.sign('HMAC', key, enc.encode(message));
  return b64urlEncode(String.fromCharCode(...new Uint8Array(sig)));
}

// 签发令牌：base64url(payload JSON) + '.' + 签名；密钥为派生密钥（见 tokenKey）
async function makeToken(payload, secret) {
  const body = b64urlEncode(JSON.stringify(payload));
  return body + '.' + (await hmacSha256B64url(secret, body));
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

// 令牌派生密钥：HMAC(SK, 版本标识 | Bucket | 密码哈希)
// → 修改 UPLOAD_PASSWORD 立即作废全部已签发令牌（密钥变了，旧签名验不过）；
//   不同 Bucket 的部署实例之间令牌互不通用（防跨实例认证绕过）；无需新增环境变量。
async function tokenKey(env) {
  const fp = await sha256Hex(env.UPLOAD_PASSWORD || '');
  return hmacSha256B64url(env.OSS_ACCESS_KEY_SECRET, 'yunwo-auth-v1|' + env.OSS_BUCKET + '|' + fp);
}

// 登录会话令牌：7 天硬到期、不续期——到期必须重新输入密码。
// 防止"令牌换令牌"无限续期导致事实上的永久会话。
const AUTH_TOKEN_TTL = 7 * 24 * 3600;
async function makeAuthToken(env) {
  return makeToken({ t: 'auth', e: Math.floor(Date.now() / 1000) + AUTH_TOKEN_TTL }, await tokenKey(env));
}

// 统一鉴权：返回 'pwd'（密码通过）/ 'token'（令牌通过）/ null（失败）
// 匿名模式（显式 ALLOW_ANONYMOUS_UPLOAD=true）下密码为空恒通过，返回 'pwd'
// 注意：令牌字段名用 auth，避免与 list.js 的分页游标 token 冲突
async function verifyAuth(body, env) {
  if (await pwdOk(body.password, env.UPLOAD_PASSWORD)) return 'pwd';
  const p = await readToken(body.auth, await tokenKey(env));
  return (p && p.t === 'auth') ? 'token' : null;
}

// 请求硬化：限制请求体与敏感字段长度，防畸形请求消耗边缘函数资源
// （真正的按 IP 限流需在平台 WAF 层配置，见 README「安全提示」）
const MAX_BODY_BYTES = 8192;
function badInput(body) {
  if (!body || typeof body !== 'object') return '请求体必须是 JSON 对象';
  const limits = { password: 128, auth: 2048, session: 2048, token: 2048, filename: 256, dir: 16 };
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

const IMG_EXTS = ['jpg', 'jpeg', 'png', 'gif', 'webp', 'svg', 'avif', 'bmp', 'ico', 'tiff'];
const VIDEO_EXTS = ['mp4', 'webm', 'mov', 'mkv', 'm4v', 'avi', 'flv', 'ts'];

// 文件主体名清洗：保留中文 / 字母数字 / . _ -，其余字符替换为 -，折叠重复、去首尾点与连字符，
// 最长 80 字符。与 delete/rename/multipart/upload 的 KEY_RE / NAME_RE 白名单保持一致。
function sanitizeBaseName(filename) {
  let base = String(filename).replace(/\.[^.]*$/, ''); // 去掉最后一个扩展名
  base = base.replace(/[\/\\]/g, '-');
  base = base.replace(/[^A-Za-z0-9._\-一-鿿㐀-䶿]/g, '-'); // 一-鿿 = CJK 基本区，㐀-䶿 = 扩展 A 区
  base = base.replace(/-{2,}/g, '-').replace(/^[.\-]+|[.\-]+$/g, '');
  if (base.length > 80) base = base.slice(0, 80).replace(/[.\-]+$/, '');
  return base;
}

// 按扩展名归类目录，生成对象键：upweb/img/20260824/xxx.webp
// keepName=true 时用清洗后的原文件名（同名冲突会被 x-oss-forbid-overwrite 拒绝，不会静默覆盖）；
// 否则用随机 UUID。
function makeObjectKey(filename, keepName) {
  const ext = filename.includes('.') ? (filename.split('.').pop() || 'bin').toLowerCase().replace(/[^a-z0-9]/g, '').slice(0, 8) || 'bin' : 'bin';
  const dir = IMG_EXTS.includes(ext) ? 'upweb/img'
    : VIDEO_EXTS.includes(ext) ? 'upweb/video'
    : 'upweb/other';
  const d = new Date();
  const datePath = d.getFullYear() + String(d.getMonth() + 1).padStart(2, '0') + String(d.getDate()).padStart(2, '0');
  let base = keepName ? sanitizeBaseName(filename) : '';
  if (!base) base = crypto.randomUUID().replace(/-/g, ''); // 清洗后为空（如纯表情文件名）则回退随机名
  return `${dir}/${datePath}/${base}.${ext}`;
}

// 对象键逐段编码（保留 / 分隔符），用于拼接 URL 路径（中文文件名必须编码）
function encodeKeyPath(key) {
  return key.split('/').map(encodeURIComponent).join('/');
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

  const { body, err } = await readJsonBody(request, MAX_BODY_BYTES);
  if (err) return err;
  const inputErr = badInput(body);
  if (inputErr) return jsonResponse({ error: inputErr }, 400);

  const maxMB = parseInt(env.MAX_SIZE_MB, 10) || 100;
  const maxSize = maxMB * 1024 * 1024;

  // 密码预检：前端登录门禁专用，只验证身份、不生成签名。
  // 仅密码验证通过才签发 7 天登录令牌；持令牌预检不续签（7 天硬到期后重新输密码）。
  if (body.check === true) {
    const authBy = await verifyAuth(body, env);
    if (!authBy) {
      return rejectAuth();
    }
    const resp = { ok: true, needPassword: !!env.UPLOAD_PASSWORD, maxMB };
    if (authBy === 'pwd' && env.UPLOAD_PASSWORD) resp.token = await makeAuthToken(env);
    return jsonResponse(resp);
  }

  // 上传鉴权（密码或登录令牌）
  if (!(await verifyAuth(body, env))) {
    return rejectAuth();
  }

  const size = parseInt(body.size, 10) || 0;
  if (size <= 0 || size > maxSize) {
    return jsonResponse({ error: `文件大小超限（上限 ${maxMB}MB）` }, 400);
  }

  const objectKey = makeObjectKey(body.filename || 'file.bin', body.keepName === true);

  // PostObject Policy：10 分钟有效；大小受限；bucket 与 key 精确绑定本次生成；
  // x-oss-forbid-overwrite 也写进 Policy 条件，客户端无法剥离该字段来覆盖已有对象
  const policyObj = {
    expiration: new Date(Date.now() + 10 * 60 * 1000).toISOString(),
    conditions: [
      { bucket: env.OSS_BUCKET },
      ['content-length-range', 1, maxSize],
      ['eq', '$key', objectKey],
      ['eq', '$x-oss-forbid-overwrite', 'true'],
    ],
  };
  const policy = btoa(JSON.stringify(policyObj));
  const signature = await hmacSha1Base64(env.OSS_ACCESS_KEY_SECRET, policy);

  return jsonResponse({
    host: `https://${env.OSS_BUCKET}.${env.OSS_ENDPOINT}`,
    fields: {
      key: objectKey,
      policy,
      OSSAccessKeyId: env.OSS_ACCESS_KEY_ID,
      success_action_status: '200',
      signature,
      'x-oss-forbid-overwrite': 'true', // 双保险：禁止覆盖同名对象
    },
    url: `${env.PUBLIC_URL_BASE.replace(/\/$/, '')}/${encodeKeyPath(objectKey)}`,
    dir: objectKey.split('/').slice(0, 2).join('/'), // 如 upweb/img
  });
}

// EdgeOne Pages Functions / Cloudflare Pages Functions 入口
export async function onRequestPost(context) {
  return handle(context.request, context.env);
}
export async function onRequest(context) {
  return handle(context.request, context.env);
}
