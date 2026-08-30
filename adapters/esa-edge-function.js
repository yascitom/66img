// ============================================================
// OSS 直传签名 —— 阿里云 ESA 边缘函数（Edge Routine）版
// 路由：POST /api/sign、POST /api/list、POST /api/delete、POST /api/rename（改名/移动目录）、POST /api/multipart（大文件分片上传）、POST /api/upload（PicGo 兼容直传）
// 部署：ESA 控制台 → 边缘函数 → 新建函数 → 粘贴本文件 → 发布 →
//       在「函数路由/域名关联」中把你的管理站点域名关联到本函数
// 注意：ESA 边缘函数若不支持控制台环境变量，直接在下方 CONFIG 里填写即可
//       （填了 CONFIG 的代码文件不要再提交到公开仓库！）
// 前端 index.html 可部署在 ESA Pages 或任何静态托管上，
// 本函数已放开 /api/* 的 CORS。
// ============================================================

// 如果 ESA 没有配环境变量的入口，就在这里直接填（优先级高于环境变量）：
const CONFIG = {
  OSS_ACCESS_KEY_ID: '',
  OSS_ACCESS_KEY_SECRET: '',
  OSS_BUCKET: '',
  OSS_ENDPOINT: '',       // 如 oss-cn-hongkong.aliyuncs.com
  PUBLIC_URL_BASE: '',    // 如 https://img.example.com（你的 CF 免流域名）
  UPLOAD_PASSWORD: '',    // 必填，至少 10 位；未配置或太短将拒绝服务
  ALLOW_ANONYMOUS_UPLOAD: '', // 可选，显式填 true 才允许免密码公开上传（不推荐）
  MAX_SIZE_MB: '',        // 可选，默认 100
  PART_SIZE_MB: '',       // 可选，分片大小（MB），默认 10，范围 5~100
};

const CORS = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Methods': 'POST, OPTIONS',
  'Access-Control-Allow-Headers': 'Content-Type',
};

function getEnv(key) {
  if (CONFIG[key]) return CONFIG[key];
  if (typeof globalThis !== 'undefined' && globalThis.ENV && globalThis.ENV[key]) return globalThis.ENV[key];
  return '';
}

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
function authConfigError() {
  const p = getEnv('UPLOAD_PASSWORD');
  if (!p) {
    if (String(getEnv('ALLOW_ANONYMOUS_UPLOAD')) === 'true') return '';
    return '服务端未配置 UPLOAD_PASSWORD，已拒绝服务。请设置上传密码（≥10 位）；如确需完全公开，显式设置 ALLOW_ANONYMOUS_UPLOAD=true';
  }
  if (String(p).length < 10) {
    return 'UPLOAD_PASSWORD 强度不足（至少需 10 位），已拒绝服务。请修改为强密码';
  }
  return '';
}

// 入参为 Latin-1 字节串（如 HMAC 签名）；含中日韩的 JSON 请用 b64urlJsonEncode
function b64urlEncode(s) { return btoa(s).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, ''); }

// UTF-8 安全 base64：btoa 只接受 Latin-1，含中日韩等字符的字符串需先按 UTF-8 转字节再编码
function b64utf8(s) {
  return btoa(String.fromCharCode(...new TextEncoder().encode(s)));
}

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

// 令牌派生密钥：HMAC(SK, 版本标识 | Bucket | 密码哈希)
// → 修改 UPLOAD_PASSWORD 立即作废全部已签发令牌；不同 Bucket 的部署实例令牌互不通用；
//   无需新增环境变量。
async function tokenKey() {
  const fp = await sha256Hex(getEnv('UPLOAD_PASSWORD') || '');
  return hmacSha256B64url(getEnv('OSS_ACCESS_KEY_SECRET'), 'yunwo-auth-v1|' + getEnv('OSS_BUCKET') + '|' + fp);
}

// 登录会话令牌：7 天硬到期、不续期——到期必须重新输入密码
const AUTH_TOKEN_TTL = 7 * 24 * 3600;
async function makeAuthToken() {
  return makeToken({ t: 'auth', e: Math.floor(Date.now() / 1000) + AUTH_TOKEN_TTL }, await tokenKey());
}

// 统一鉴权：返回 'pwd'（密码通过）/ 'token'（令牌通过）/ null（失败）
// 匿名模式（显式 ALLOW_ANONYMOUS_UPLOAD=true）下密码为空恒通过，返回 'pwd'
async function verifyAuth(body) {
  if (await pwdOk(body.password, getEnv('UPLOAD_PASSWORD'))) return 'pwd';
  const p = await readToken(body.auth, await tokenKey());
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
async function makeMpToken(key, uploadId, size, partSize) {
  return makeToken({
    t: 'mp', k: key, u: uploadId, s: size,
    m: Math.ceil(size / partSize),
    z: partSize, // 分片大小（complete 逐片核验用）
    e: Math.floor(Date.now() / 1000) + MP_TOKEN_TTL,
  }, await tokenKey());
}
async function mpSession(body, key, uploadId) {
  const p = await readToken(body.session, await tokenKey());
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
async function listObjects(token, dir) {
  const bucket = getEnv('OSS_BUCKET');
  const endpoint = getEnv('OSS_ENDPOINT');
  const prefix = DIR_PREFIX[dir] || DIR_PREFIX.all;
  const params = new URLSearchParams({ 'list-type': '2', prefix: prefix, 'max-keys': '60' });
  if (token) params.set('continuation-token', token);
  const url = `https://${bucket}.${endpoint}/?${params.toString()}`;
  const date = new Date().toUTCString();
  const myStringToSign = 'GET\n\n\n\nx-oss-date:' + date + '\n/' + bucket + '/?list-type=2';
  const headers = {
    'x-oss-date': date,
    Authorization: `OSS ${getEnv('OSS_ACCESS_KEY_ID')}:${await hmacSha1Base64(getEnv('OSS_ACCESS_KEY_SECRET'), myStringToSign)}`,
  };
  let r = await fetchWithRetry(url, { headers });
  let xml = await r.text();
  if (!r.ok) {
    const code = (xml.match(/<Code>([^<]+)<\/Code>/) || [])[1] || r.status;
    const ossString = (xml.match(/<StringToSign>([\s\S]*?)<\/StringToSign>/) || [])[1];
    if (code === 'SignatureDoesNotMatch' && ossString) {
      const ossStr = xmlUnescape(ossString);
      headers.Authorization = `OSS ${getEnv('OSS_ACCESS_KEY_ID')}:${await hmacSha1Base64(getEnv('OSS_ACCESS_KEY_SECRET'), ossStr)}`;
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
    files.push({ key: key, time: m[2], size: parseInt(m[3], 10), type: typeOf(key), url: getEnv('PUBLIC_URL_BASE').replace(/\/$/, '') + '/' + encodeKeyPath(key) });
  }
  const nextToken = (xml.match(/<NextContinuationToken>([^<]*)<\/NextContinuationToken>/) || [])[1] || '';
  const truncated = /<IsTruncated>true<\/IsTruncated>/.test(xml);
  return { files, nextToken, truncated };
}

async function handleList(request) {
  const required = ['OSS_ACCESS_KEY_ID', 'OSS_ACCESS_KEY_SECRET', 'OSS_BUCKET', 'OSS_ENDPOINT', 'PUBLIC_URL_BASE'];
  for (const k of required) {
    if (!getEnv(k)) return jsonResponse({ error: `服务端缺少配置 ${k}` }, 500);
  }
  const cfgErr = authConfigError();
  if (cfgErr) return jsonResponse({ error: cfgErr }, 500);
  const { body, err } = await readJsonBody(request, MAX_BODY_BYTES);
  if (err) return err;
  const inputErr = badInput(body);
  if (inputErr) return jsonResponse({ error: inputErr }, 400);
  if (!(await verifyAuth(body))) {
    return rejectAuth();
  }
  try {
    return jsonResponse(await listObjects(body.token || '', String(body.dir || 'all')));
  } catch (e) {
    return jsonResponse({ error: e.message }, 502);
  }
}

// OSS DeleteObject：用 x-oss-date 替代 Date 头，自愈重试逻辑同 listObjects
// StringToSign = DELETE\n\n\n\nx-oss-date:<date>\n/<bucket>/<key>
async function deleteObject(key) {
  const bucket = getEnv('OSS_BUCKET');
  const endpoint = getEnv('OSS_ENDPOINT');
  const url = `https://${bucket}.${endpoint}/${key.split('/').map(encodeURIComponent).join('/')}`;
  const date = new Date().toUTCString();
  const myStringToSign = 'DELETE\n\n\n\nx-oss-date:' + date + '\n/' + bucket + '/' + key;
  const headers = {
    'x-oss-date': date,
    Authorization: `OSS ${getEnv('OSS_ACCESS_KEY_ID')}:${await hmacSha1Base64(getEnv('OSS_ACCESS_KEY_SECRET'), myStringToSign)}`,
  };
  let r = await fetchWithRetry(url, { method: 'DELETE', headers });
  if (!r.ok && r.status !== 204) {
    const xml = await r.text();
    const code = (xml.match(/<Code>([^<]+)<\/Code>/) || [])[1] || r.status;
    const ossString = (xml.match(/<StringToSign>([\s\S]*?)<\/StringToSign>/) || [])[1];
    if (code === 'SignatureDoesNotMatch' && ossString) {
      const ossStr = xmlUnescape(ossString);
      headers.Authorization = `OSS ${getEnv('OSS_ACCESS_KEY_ID')}:${await hmacSha1Base64(getEnv('OSS_ACCESS_KEY_SECRET'), ossStr)}`;
      r = await fetchWithRetry(url, { method: 'DELETE', headers });
      if (!r.ok && r.status !== 204) {
        const xml2 = await r.text();
        const code2 = (xml2.match(/<Code>([^<]+)<\/Code>/) || [])[1] || r.status;
        // 签名排障细节（双方 StringToSign）只进平台日志，不进响应体
        console.error('OSS 删除重签仍失败：', code2, '｜OSS期望[', ossStr, ']｜我方[', myStringToSign, ']');
        throw new Error('OSS 删除失败：' + code2);
      }
    } else {
      throw new Error('OSS 删除失败：' + code);
    }
  }
}

async function handleDelete(request) {
  const required = ['OSS_ACCESS_KEY_ID', 'OSS_ACCESS_KEY_SECRET', 'OSS_BUCKET', 'OSS_ENDPOINT'];
  for (const k of required) {
    if (!getEnv(k)) return jsonResponse({ error: `服务端缺少配置 ${k}` }, 500);
  }
  const cfgErr = authConfigError();
  if (cfgErr) return jsonResponse({ error: cfgErr }, 500);
  const { body, err } = await readJsonBody(request, MAX_BODY_BYTES);
  if (err) return err;
  const inputErr = badInput(body);
  if (inputErr) return jsonResponse({ error: inputErr }, 400);
  if (!(await verifyAuth(body))) {
    return rejectAuth();
  }
  const key = String(body.key || '');
  if (!validMpKey(key)) {
    return jsonResponse({ error: '仅允许删除 upweb/ 前缀下的文件' }, 400);
  }
  try {
    await deleteObject(key);
    return jsonResponse({ ok: true, key });
  } catch (e) {
    return jsonResponse({ error: e.message }, 502);
  }
}

// OSS CopyObject（同桶复制，重命名前半步）
// StringToSign = PUT\n\n\n\nx-oss-copy-source:<src>\nx-oss-date:<date>\nx-oss-forbid-overwrite:true\n/<bucket>/<newKey>
// x-oss-forbid-overwrite:true —— 目标已存在则拒绝，防止改名覆盖掉别的文件
async function copyObject(oldKey, newKey) {
  const bucket = getEnv('OSS_BUCKET');
  const endpoint = getEnv('OSS_ENDPOINT');
  const enc = k => k.split('/').map(encodeURIComponent).join('/');
  const url = `https://${bucket}.${endpoint}/${enc(newKey)}`;
  const copySource = '/' + bucket + '/' + enc(oldKey);
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
    Authorization: `OSS ${getEnv('OSS_ACCESS_KEY_ID')}:${await hmacSha1Base64(getEnv('OSS_ACCESS_KEY_SECRET'), myStringToSign)}`,
  };
  let r = await fetchWithRetry(url, { method: 'PUT', headers });
  if (!r.ok) {
    const xml = await r.text();
    const code = (xml.match(/<Code>([^<]+)<\/Code>/) || [])[1] || r.status;
    if (code === 'FileAlreadyExists') { const e = new Error('目标文件名已存在，请换一个名字'); e.code = 'CONFLICT'; throw e; }
    const ossString = (xml.match(/<StringToSign>([\s\S]*?)<\/StringToSign>/) || [])[1];
    if (code === 'SignatureDoesNotMatch' && ossString) {
      const ossStr = xmlUnescape(ossString);
      headers.Authorization = `OSS ${getEnv('OSS_ACCESS_KEY_ID')}:${await hmacSha1Base64(getEnv('OSS_ACCESS_KEY_SECRET'), ossStr)}`;
      r = await fetchWithRetry(url, { method: 'PUT', headers });
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
async function handleRename(request) {
  const required = ['OSS_ACCESS_KEY_ID', 'OSS_ACCESS_KEY_SECRET', 'OSS_BUCKET', 'OSS_ENDPOINT', 'PUBLIC_URL_BASE'];
  for (const k of required) {
    if (!getEnv(k)) return jsonResponse({ error: `服务端缺少配置 ${k}` }, 500);
  }
  const cfgErr = authConfigError();
  if (cfgErr) return jsonResponse({ error: cfgErr }, 500);
  const { body, err } = await readJsonBody(request, MAX_BODY_BYTES);
  if (err) return err;
  const inputErr = badInput(body);
  if (inputErr) return jsonResponse({ error: inputErr }, 400);
  if (!(await verifyAuth(body))) {
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
    return jsonResponse({ ok: true, key, url: getEnv('PUBLIC_URL_BASE').replace(/\/$/, '') + '/' + newKey.split('/').map(encodeURIComponent).join('/') });
  }
  try {
    await copyObject(key, newKey);
    const okUrl = getEnv('PUBLIC_URL_BASE').replace(/\/$/, '') + '/' + newKey.split('/').map(encodeURIComponent).join('/');
    try {
      await deleteObject(key);
    } catch (e2) {
      // 新 key 已复制成功、旧 key 删除失败：不谎报失败（新文件已可用），
      // 返回成功并带 warn，由前端提示用户手动清理旧文件，避免「失败→重试→更多残留」
      return jsonResponse({ ok: true, key: newKey, oldKey: key, warn: '新文件已完成，但旧文件删除失败（新旧两份并存），请稍后手动删除旧文件', url: okUrl });
    }
    return jsonResponse({ ok: true, key: newKey, oldKey: key, url: okUrl });
  } catch (e) {
    return jsonResponse({ error: e.message }, e.code === 'CONFLICT' ? 409 : 502);
  }
}

async function handleSign(request) {
  const required = ['OSS_ACCESS_KEY_ID', 'OSS_ACCESS_KEY_SECRET', 'OSS_BUCKET', 'OSS_ENDPOINT', 'PUBLIC_URL_BASE'];
  for (const k of required) {
    if (!getEnv(k)) return jsonResponse({ error: `服务端缺少配置 ${k}` }, 500);
  }
  const cfgErr = authConfigError();
  if (cfgErr) return jsonResponse({ error: cfgErr }, 500);
  const { body, err } = await readJsonBody(request, MAX_BODY_BYTES);
  if (err) return err;
  const inputErr = badInput(body);
  if (inputErr) return jsonResponse({ error: inputErr }, 400);

  const pwd = getEnv('UPLOAD_PASSWORD');
  const maxMB = parseInt(getEnv('MAX_SIZE_MB'), 10) || 100;
  const maxSize = maxMB * 1024 * 1024;

  // 密码预检：前端登录门禁专用；仅密码通过才签发 7 天令牌，持令牌预检不续签
  if (body.check === true) {
    const authBy = await verifyAuth(body);
    if (!authBy) {
      return rejectAuth();
    }
    const resp = { ok: true, needPassword: !!pwd, maxMB };
    if (authBy === 'pwd' && pwd) resp.token = await makeAuthToken();
    return jsonResponse(resp);
  }

  if (!(await verifyAuth(body))) {
    return rejectAuth();
  }

  const size = parseInt(body.size, 10) || 0;
  if (size <= 0 || size > maxSize) {
    return jsonResponse({ error: `文件大小超限（上限 ${maxMB}MB）` }, 400);
  }

  const objectKey = makeObjectKey(body.filename || 'file.bin', body.keepName === true);
  const policy = b64utf8(JSON.stringify({
    expiration: new Date(Date.now() + 10 * 60 * 1000).toISOString(),
    conditions: [
      { bucket: getEnv('OSS_BUCKET') },
      ['content-length-range', 1, maxSize],
      ['eq', '$key', objectKey],
      ['eq', '$x-oss-forbid-overwrite', 'true'],
    ],
  }));
  const signature = await hmacSha1Base64(getEnv('OSS_ACCESS_KEY_SECRET'), policy);

  return jsonResponse({
    host: `https://${getEnv('OSS_BUCKET')}.${getEnv('OSS_ENDPOINT')}`,
    fields: {
      key: objectKey,
      policy,
      OSSAccessKeyId: getEnv('OSS_ACCESS_KEY_ID'),
      success_action_status: '200',
      signature,
      'x-oss-forbid-overwrite': 'true',
    },
    url: `${getEnv('PUBLIC_URL_BASE').replace(/\/$/, '')}/${encodeKeyPath(objectKey)}`,
    dir: objectKey.split('/').slice(0, 2).join('/'),
  });
}

// ================= PicGo / 第三方客户端兼容上传（POST /api/upload） =================
// 接收 multipart/form-data 文件，服务端签名后直接 PutObject 写入 OSS，返回 PicGo 兼容 JSON。
// 鉴权（任一）：Authorization: Bearer <密码或令牌> / x-yunwo-password 头 / 表单 password 或 auth 字段。
// PicGo 配置：API 地址 https://你的域名/api/upload，POST 参数名 file，返回 JSON 路径 data.url，
//   自定义请求头 {"Authorization":"Bearer 你的上传密码"}。
// 默认保留原文件名（表单 keepname=0/false 关闭）；同名冲突返回 409，绝不静默覆盖。
// 注意：文件内容会读入边缘函数内存，MAX_SIZE_MB 勿超过平台请求体限制。

function picgoOk(url, key, name, size) {
  return jsonResponse({ success: true, code: 200, message: 'ok', result: [url], data: { url, key, name, size } });
}
function picgoErr(message, status) {
  return jsonResponse({ success: false, code: status, message, error: message }, status);
}

// 服务端签名 PutObject（V1 Header 签名）+ 签名自愈重试一次；x-oss-forbid-overwrite 写死
async function putObject(key, bytes, contentType) {
  const bucket = getEnv('OSS_BUCKET');
  const endpoint = getEnv('OSS_ENDPOINT');
  const url = `https://${bucket}.${endpoint}/${encodeKeyPath(key)}`;
  const date = new Date().toUTCString();
  // x-oss- 头按名称字典序进入待签串：x-oss-date < x-oss-forbid-overwrite
  const myStringToSign = `PUT\n\n${contentType}\n\nx-oss-date:${date}\nx-oss-forbid-overwrite:true\n/${bucket}/${key}`;
  const headers = {
    'x-oss-date': date,
    'x-oss-forbid-overwrite': 'true',
    'Content-Type': contentType,
    Authorization: `OSS ${getEnv('OSS_ACCESS_KEY_ID')}:${await hmacSha1Base64(getEnv('OSS_ACCESS_KEY_SECRET'), myStringToSign)}`,
  };
  let r = await fetchWithRetry(url, { method: 'PUT', headers, body: bytes });
  let xml = await r.text();
  if (!r.ok) {
    const code = (xml.match(/<Code>([^<]+)<\/Code>/) || [])[1] || r.status;
    const ossString = (xml.match(/<StringToSign>([\s\S]*?)<\/StringToSign>/) || [])[1];
    if (code === 'SignatureDoesNotMatch' && ossString) {
      const ossStr = xmlUnescape(ossString);
      headers.Authorization = `OSS ${getEnv('OSS_ACCESS_KEY_ID')}:${await hmacSha1Base64(getEnv('OSS_ACCESS_KEY_SECRET'), ossStr)}`;
      r = await fetchWithRetry(url, { method: 'PUT', headers, body: bytes });
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

// ------------------------------------------------------------
// 带字节硬上限读取请求体：超限即中断流，返回 null。
// Content-Length 缺失或谎报时也不能超过 cap（防未鉴权大体积消耗）。
// ------------------------------------------------------------
async function readBodyCapped(request, cap) {
  if (!request.body) return new Uint8Array(0);
  const reader = request.body.getReader();
  const chunks = [];
  let total = 0;
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    total += value.byteLength;
    if (total > cap) {
      await reader.cancel().catch(() => {});
      return null;
    }
    chunks.push(value);
  }
  const buf = new Uint8Array(total);
  let off = 0;
  for (const c of chunks) { buf.set(c, off); off += c.byteLength; }
  return buf;
}

async function handleUpload(request) {
  const required = ['OSS_ACCESS_KEY_ID', 'OSS_ACCESS_KEY_SECRET', 'OSS_BUCKET', 'OSS_ENDPOINT', 'PUBLIC_URL_BASE'];
  for (const k of required) {
    if (!getEnv(k)) return picgoErr(`服务端缺少配置 ${k}`, 500);
  }
  const cfgErr = authConfigError();
  if (cfgErr) return picgoErr(cfgErr, 500);

  const maxMB = parseInt(getEnv('MAX_SIZE_MB'), 10) || 100;
  const maxSize = maxMB * 1024 * 1024;
  // Content-Type 预检（不花大钱，先做）
  const ct = request.headers.get('Content-Type') || '';
  if (!ct.toLowerCase().startsWith('multipart/form-data')) {
    return picgoErr('Content-Type 必须是 multipart/form-data', 400);
  }
  // Content-Length 快路径：超限直接 413（multipart 开销放宽 2MB）；头不可信时由 readBodyCapped 硬上限兜底
  const cl = parseInt(request.headers.get('Content-Length') || '0', 10);
  if (cl > maxSize + 2 * 1024 * 1024) {
    return picgoErr(`文件大小超限（上限 ${maxMB}MB）`, 413);
  }

  // 鉴权前置：头里有凭据（Bearer / x-yunwo-password）先验证，通过才读 body，
  // 杜绝未鉴权的大体积 multipart 白耗内存与函数时长
  const creds = { password: '', auth: '' };
  const m = (request.headers.get('Authorization') || '').match(/^Bearer\s+(.+)$/i);
  if (m) { creds.password = m[1]; creds.auth = m[1]; }
  const hdrPwd = request.headers.get('x-yunwo-password');
  if (hdrPwd) creds.password = hdrPwd;
  if (creds.password.length > 128 || creds.auth.length > 2048) {
    return picgoErr('鉴权参数非法', 400);
  }
  const hasHeaderCreds = !!(creds.password || creds.auth);
  let authed = false;
  if (hasHeaderCreds) {
    if (!(await verifyAuth(creds))) {
      await new Promise(r => setTimeout(r, 400));
      return picgoErr('上传密码错误或会话已过期', 401);
    }
    authed = true;
  }

  // 读取 body：字节硬上限，超限即中断（无 CL / CL 谎报也过不了）
  const buf = await readBodyCapped(request, maxSize + 2 * 1024 * 1024);
  if (!buf) {
    return picgoErr(`文件大小超限（上限 ${maxMB}MB）`, 413);
  }
  let form;
  try {
    form = await new Response(buf, { headers: { 'Content-Type': ct } }).formData();
  } catch {
    return picgoErr('表单解析失败', 400);
  }

  // 头里没带凭据时回退到表单字段鉴权（兼容无法自定义头的客户端）
  if (!authed) {
    const fPwd = form.get('password');
    const fAuth = form.get('auth');
    if (typeof fPwd === 'string' && fPwd) creds.password = fPwd;
    if (typeof fAuth === 'string' && fAuth) creds.auth = fAuth;
    if (creds.password.length > 128 || creds.auth.length > 2048) {
      return picgoErr('鉴权参数非法', 400);
    }
    if (!(await verifyAuth(creds))) {
      await new Promise(r => setTimeout(r, 400));
      return picgoErr('上传密码错误或会话已过期', 401);
    }
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

  const kn = String(form.get('keepname') || '').toLowerCase();
  const keepName = kn !== '0' && kn !== 'false';
  const key = makeObjectKey(file.name || 'file.bin', keepName);

  try {
    const bytes = await file.arrayBuffer();
    const mime = (file.type || 'application/octet-stream').slice(0, 100);
    await putObject(key, bytes, mime);
    const url = `${getEnv('PUBLIC_URL_BASE').replace(/\/$/, '')}/${encodeKeyPath(key)}`;
    return picgoOk(url, key, file.name, file.size);
  } catch (e) {
    if (e.code === 'CONFLICT') return picgoErr(e.message, 409);
    console.error('upload failed:', e && e.message); // 细节留在平台日志，不外泄
    return picgoErr('OSS 写入失败', 502);
  }
}

// ================= 分片上传（Multipart Upload） =================
// action=init      服务端调 InitiateMultipartUpload，返回 uploadId + key
// action=part      为单个分片签发预签名 URL（1 小时有效），浏览器直传 OSS
// action=complete  合并分片；action=abort 清理残留分片
// 每个分片即签即传、独立计时 → 慢网络总时长不设限，且支持断点续传。

function xmlEscape(s) {
  return String(s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;').replace(/'/g, '&#39;');
}
// key 白名单：upweb/ 前缀 + 安全字符集（字母数字 . _ - /），禁 .. 与引号/尖括号等可注入字符
const KEY_RE = /^upweb\/[A-Za-z0-9._\/\-一-鿿㐀-䶿가-힯ㄱ-ㅣ぀-ヿ]+$/; // 允许中日韩文件名（与 sign/rename 一致）
function validMpKey(key) {
  return typeof key === 'string' && key.length <= 512 && KEY_RE.test(key) && !key.includes('..');
}
function encodeKeyPath(key) {
  return key.split('/').map(encodeURIComponent).join('/');
}

// 带超时与瞬时故障重试的 fetch：边缘运行时到 OSS 的子请求偶发 net_exception_timeout 等
// 网络抖动，单次抖动不应判死一次已传了几十分钟的分片上传。仅网络层错误重试；
// OSS 已应答的业务错误（4xx/NoSuchUpload/CONFLICT 等）不在此层处理，交由调用方判断。
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

// 服务端签名直调 OSS（init/complete/abort），V1 Header 签名 + 签名自愈重试
// forbidOverwrite=true 时带 x-oss-forbid-overwrite（complete 防静默覆盖用；字典序 x-oss-date < x-oss-forbid-overwrite）
async function ossRequest(method, key, subResource, contentType, bodyText, forbidOverwrite, extraHeaders) {
  const bucket = getEnv('OSS_BUCKET');
  const endpoint = getEnv('OSS_ENDPOINT');
  const url = `https://${bucket}.${endpoint}/${encodeKeyPath(key)}${subResource}`;
  const date = new Date().toUTCString();
  const canonicalizedResource = `/${bucket}/${key}${subResource}`;
  const ossHeaders = forbidOverwrite ? `x-oss-date:${date}\nx-oss-forbid-overwrite:true\n` : `x-oss-date:${date}\n`;
  const myStringToSign = `${method}\n\n${contentType || ''}\n\n${ossHeaders}${canonicalizedResource}`;
  const headers = {
    'x-oss-date': date,
    Authorization: `OSS ${getEnv('OSS_ACCESS_KEY_ID')}:${await hmacSha1Base64(getEnv('OSS_ACCESS_KEY_SECRET'), myStringToSign)}`,
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
      headers.Authorization = `OSS ${getEnv('OSS_ACCESS_KEY_ID')}:${await hmacSha1Base64(getEnv('OSS_ACCESS_KEY_SECRET'), ossStr)}`;
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

// 对象存在性检查：GET + Range: bytes=0-0（复用 ossRequest 的签名自愈与超时重试）
// 存在 → 206（1 字节 body）；不存在 → 404（NoSuchKey）；0 字节对象 → 416（InvalidRange，同样证明存在）。
// Range 是普通请求头，不参与 V1 签名计算；响应一律有 body，边缘运行时不会干等。
async function ossObjectExists(key) {
  try {
    await ossRequest('GET', key, '', '', null, false, { Range: 'bytes=0-0' });
    return true; // 2xx（206 Partial Content）→ 存在
  } catch (e) {
    if (/NoSuchKey|404|NoSuchObject/.test(e.message)) return false;
    if (/InvalidRange|416/.test(e.message)) return true; // 0 字节对象：416 同样证明存在
    throw e;
  }
}

// 为单个分片签发预签名 URL（V1 URL 签名）
// StringToSign = PUT\n\n{Content-Type}\n{Expires}\n/{bucket}/{key}?partNumber={n}&uploadId={id}
async function signPartUrl(key, uploadId, partNumber, mime) {
  const bucket = getEnv('OSS_BUCKET');
  const expires = Math.floor(Date.now() / 1000) + 3600;
  const stringToSign = `PUT\n\n${mime}\n${expires}\n/${bucket}/${key}?partNumber=${partNumber}&uploadId=${uploadId}`;
  const signature = await hmacSha1Base64(getEnv('OSS_ACCESS_KEY_SECRET'), stringToSign);
  return `https://${bucket}.${getEnv('OSS_ENDPOINT')}/${encodeKeyPath(key)}`
    + `?partNumber=${partNumber}&uploadId=${encodeURIComponent(uploadId)}`
    + `&OSSAccessKeyId=${encodeURIComponent(getEnv('OSS_ACCESS_KEY_ID'))}`
    + `&Expires=${expires}&Signature=${encodeURIComponent(signature)}`;
}

async function handleMultipart(request) {
  const required = ['OSS_ACCESS_KEY_ID', 'OSS_ACCESS_KEY_SECRET', 'OSS_BUCKET', 'OSS_ENDPOINT', 'PUBLIC_URL_BASE'];
  for (const k of required) {
    if (!getEnv(k)) return jsonResponse({ error: `服务端缺少配置 ${k}` }, 500);
  }
  const cfgErr = authConfigError();
  if (cfgErr) return jsonResponse({ error: cfgErr }, 500);
  const { body, err } = await readJsonBody(request, 1024 * 1024);
  if (err) return err;
  const inputErr = badInput(body);
  if (inputErr) return jsonResponse({ error: inputErr }, 400);
  if (!(await verifyAuth(body))) {
    return rejectAuth();
  }

  const maxMB = parseInt(getEnv('MAX_SIZE_MB'), 10) || 100;
  const maxSize = maxMB * 1024 * 1024;
  let partMB = parseInt(getEnv('PART_SIZE_MB'), 10) || 10;
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
      // 保留原文件名时做存在性预检（提前 409，避免白传分片）；
      // complete 另带 x-oss-forbid-overwrite 硬兜底，堵住「预检→合并」时间窗内的静默覆盖。
      // 预检需要 RAM 授权 oss:GetObject。随机 UUID key 几乎不可能碰撞，跳过预检省一次请求。
      // ⚠️ 存在性检查用 GET + Range: bytes=0-0（见 ossObjectExists 注释：
      // objectMeta 无体 200 让边缘 fetch 干等超时、HEAD 在本链路 403 且错误无响应体，两个坑都不可行）
      if (body.keepName === true) {
        if (await ossObjectExists(key)) {
          return jsonResponse({ error: `同名文件已存在：${key.split('/').pop()}（请先重命名或删除旧文件）`, code: 'CONFLICT' }, 409);
        }
      }
      const xml = await ossRequest('POST', key, '?uploads', mime, null);
      const uploadId = (xml.match(/<UploadId>([^<]+)<\/UploadId>/) || [])[1];
      if (!uploadId) throw new Error('OSS 未返回 UploadId');
      const session = await makeMpToken(key, uploadId, size, partSize);
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
      const mp = await mpSession(body, key, uploadId);
      if (!mp) return rejectSession();
      if (partNumber > mp.m) {
        return jsonResponse({ error: `分片号超出本会话上限（最多 ${mp.m} 片）`, code: 'BAD_SESSION' }, 400);
      }
      const mime = String(body.mime || 'application/octet-stream').slice(0, 100) || 'application/octet-stream';
      return jsonResponse({ url: await signPartUrl(key, uploadId, partNumber, mime), expiresIn: 3600 });
    }

    if (action === 'complete') {
      const key = String(body.key || '');
      const uploadId = String(body.uploadId || '');
      const parts = Array.isArray(body.parts) ? body.parts : [];
      if (!validMpKey(key) || !uploadId || parts.length === 0 || parts.length > 10000) {
        return jsonResponse({ error: '参数非法' }, 400);
      }
      const mp = await mpSession(body, key, uploadId);
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
        const lp = await ossRequest('GET', key, sub, '', null);
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
        await ossRequest('DELETE', key, `?uploadId=${encodeURIComponent(uploadId)}`, '', null).catch(() => {});
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
        await ossRequest('POST', key, `?uploadId=${encodeURIComponent(uploadId)}`, 'application/xml', xmlBody, true);
      } catch (e) {
        // 「合并其实成功但响应丢失」场景：重试时 uploadId 已被消费，OSS 返回 NoSuchUpload。
        // 此时若对象已存在，说明上次合并已成功——按成功处理，避免前端整包重传。
        // 存在性检查方式见 ossObjectExists 注释（objectMeta 干等超时 / HEAD 403 两个坑）
        if (!/NoSuchUpload/.test(e.message)) throw e;
        if (!(await ossObjectExists(key))) throw e; // 对象不存在 → 会话确实已失效，抛原始错误
      }
      return jsonResponse({ ok: true, key, url: `${getEnv('PUBLIC_URL_BASE').replace(/\/$/, '')}/${encodeKeyPath(key)}`, dir: key.split('/').slice(0, 2).join('/') });
    }

    if (action === 'abort') {
      const key = String(body.key || '');
      const uploadId = String(body.uploadId || '');
      if (!validMpKey(key) || !uploadId) return jsonResponse({ error: '参数非法' }, 400);
      const mp = await mpSession(body, key, uploadId);
      if (!mp) return rejectSession();
      try {
        await ossRequest('DELETE', key, `?uploadId=${encodeURIComponent(uploadId)}`, '', null);
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

async function handleRequest(request) {
  const url = new URL(request.url);
  if (request.method === 'OPTIONS') return new Response(null, { headers: CORS });
  if (url.pathname === '/api/sign' && request.method === 'POST') return handleSign(request);
  if (url.pathname === '/api/list' && request.method === 'POST') return handleList(request);
  if (url.pathname === '/api/delete' && request.method === 'POST') return handleDelete(request);
  if (url.pathname === '/api/rename' && request.method === 'POST') return handleRename(request);
  if (url.pathname === '/api/multipart' && request.method === 'POST') return handleMultipart(request);
  if (url.pathname === '/api/upload' && request.method === 'POST') return handleUpload(request);
  return jsonResponse({ error: 'Not Found. 接口：POST /api/sign、POST /api/list、POST /api/delete、POST /api/rename、POST /api/multipart、POST /api/upload。' }, 404);
}

// ESA 边缘函数入口（Service Worker 风格）
addEventListener('fetch', event => {
  event.respondWith(handleRequest(event.request));
});
