// ============================================================
// OSS 直传签名 —— 阿里云 ESA 边缘函数（Edge Routine）版
// 路由：POST /api/sign、POST /api/list、POST /api/delete、POST /api/multipart（大文件分片上传）
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

// 密码校验：SHA-256 哈希后比对；失败统一延迟 ~0.4s，拖慢在线暴力破解
async function pwdOk(input, expected) {
  if (!expected) return true;
  const enc = new TextEncoder();
  async function h(s) {
    const d = await crypto.subtle.digest('SHA-256', enc.encode(String(s == null ? '' : s)));
    return [...new Uint8Array(d)].map(b => b.toString(16).padStart(2, '0')).join('');
  }
  return (await h(input)) === (await h(expected));
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

const AUTH_TOKEN_TTL = 7 * 24 * 3600;
async function makeAuthToken() {
  return makeToken({ t: 'auth', e: Math.floor(Date.now() / 1000) + AUTH_TOKEN_TTL }, getEnv('OSS_ACCESS_KEY_SECRET'));
}

// 统一鉴权：密码 或 登录令牌（body.auth）任一通过即可（匿名模式下密码为空恒通过）
async function verifyAuth(body) {
  if (await pwdOk(body.password, getEnv('UPLOAD_PASSWORD'))) return true;
  const p = await readToken(body.auth, getEnv('OSS_ACCESS_KEY_SECRET'));
  return !!(p && p.t === 'auth');
}

const MP_TOKEN_TTL = 7 * 24 * 3600;
async function makeMpToken(key, uploadId, size, partSize) {
  return makeToken({
    t: 'mp', k: key, u: uploadId, s: size,
    m: Math.ceil(size / partSize),
    e: Math.floor(Date.now() / 1000) + MP_TOKEN_TTL,
  }, getEnv('OSS_ACCESS_KEY_SECRET'));
}
async function mpSession(body, key, uploadId) {
  const p = await readToken(body.session, getEnv('OSS_ACCESS_KEY_SECRET'));
  if (!p || p.t !== 'mp' || p.k !== key || p.u !== uploadId) return null;
  return p;
}
function rejectSession() {
  return jsonResponse({ error: '分片会话无效或已过期，请重新选择文件上传', code: 'BAD_SESSION' }, 400);
}

const IMG_EXTS = ['jpg', 'jpeg', 'png', 'gif', 'webp', 'svg', 'avif', 'bmp', 'ico', 'tiff'];
const VIDEO_EXTS = ['mp4', 'webm', 'mov', 'mkv', 'm4v', 'avi', 'flv', 'ts'];

// 按扩展名归类目录：upweb/img 图片 · upweb/video 视频 · upweb/other 其他
function makeObjectKey(filename) {
  const ext = filename.includes('.') ? (filename.split('.').pop() || 'bin').toLowerCase().replace(/[^a-z0-9]/g, '').slice(0, 8) || 'bin' : 'bin';
  const dir = IMG_EXTS.includes(ext) ? 'upweb/img'
    : VIDEO_EXTS.includes(ext) ? 'upweb/video'
    : 'upweb/other';
  const d = new Date();
  const datePath = d.getFullYear() + String(d.getMonth() + 1).padStart(2, '0') + String(d.getDate()).padStart(2, '0');
  const rand = crypto.randomUUID().replace(/-/g, '');
  return `${dir}/${datePath}/${rand}.${ext}`;
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
  let r = await fetch(url, { headers });
  let xml = await r.text();
  if (!r.ok) {
    const code = (xml.match(/<Code>([^<]+)<\/Code>/) || [])[1] || r.status;
    const ossString = (xml.match(/<StringToSign>([\s\S]*?)<\/StringToSign>/) || [])[1];
    if (code === 'SignatureDoesNotMatch' && ossString) {
      const ossStr = xmlUnescape(ossString);
      headers.Authorization = `OSS ${getEnv('OSS_ACCESS_KEY_ID')}:${await hmacSha1Base64(getEnv('OSS_ACCESS_KEY_SECRET'), ossStr)}`;
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
  let body;
  try { body = await request.json(); } catch { return jsonResponse({ error: '请求体必须是 JSON' }, 400); }
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
  let r = await fetch(url, { method: 'DELETE', headers });
  if (!r.ok && r.status !== 204) {
    const xml = await r.text();
    const code = (xml.match(/<Code>([^<]+)<\/Code>/) || [])[1] || r.status;
    const ossString = (xml.match(/<StringToSign>([\s\S]*?)<\/StringToSign>/) || [])[1];
    if (code === 'SignatureDoesNotMatch' && ossString) {
      const ossStr = xmlUnescape(ossString);
      headers.Authorization = `OSS ${getEnv('OSS_ACCESS_KEY_ID')}:${await hmacSha1Base64(getEnv('OSS_ACCESS_KEY_SECRET'), ossStr)}`;
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

async function handleDelete(request) {
  const required = ['OSS_ACCESS_KEY_ID', 'OSS_ACCESS_KEY_SECRET', 'OSS_BUCKET', 'OSS_ENDPOINT'];
  for (const k of required) {
    if (!getEnv(k)) return jsonResponse({ error: `服务端缺少配置 ${k}` }, 500);
  }
  const cfgErr = authConfigError();
  if (cfgErr) return jsonResponse({ error: cfgErr }, 500);
  let body;
  try { body = await request.json(); } catch { return jsonResponse({ error: '请求体必须是 JSON' }, 400); }
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

async function handleSign(request) {
  const required = ['OSS_ACCESS_KEY_ID', 'OSS_ACCESS_KEY_SECRET', 'OSS_BUCKET', 'OSS_ENDPOINT', 'PUBLIC_URL_BASE'];
  for (const k of required) {
    if (!getEnv(k)) return jsonResponse({ error: `服务端缺少配置 ${k}` }, 500);
  }
  const cfgErr = authConfigError();
  if (cfgErr) return jsonResponse({ error: cfgErr }, 500);

  let body;
  try { body = await request.json(); } catch { return jsonResponse({ error: '请求体必须是 JSON' }, 400); }

  const pwd = getEnv('UPLOAD_PASSWORD');
  const maxMB = parseInt(getEnv('MAX_SIZE_MB'), 10) || 100;
  const maxSize = maxMB * 1024 * 1024;

  // 密码预检：前端登录门禁专用；通过后签发 7 天登录令牌，前端不再保存明文密码
  if (body.check === true) {
    if (!(await verifyAuth(body))) {
      return rejectAuth();
    }
    return jsonResponse({ ok: true, needPassword: !!pwd, maxMB, token: await makeAuthToken() });
  }

  if (!(await verifyAuth(body))) {
    return rejectAuth();
  }

  const size = parseInt(body.size, 10) || 0;
  if (size <= 0 || size > maxSize) {
    return jsonResponse({ error: `文件大小超限（上限 ${maxMB}MB）` }, 400);
  }

  const objectKey = makeObjectKey(body.filename || 'file.bin');
  const policy = btoa(JSON.stringify({
    expiration: new Date(Date.now() + 10 * 60 * 1000).toISOString(),
    conditions: [['content-length-range', 1, maxSize], ['eq', '$key', objectKey]],
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
    url: `${getEnv('PUBLIC_URL_BASE').replace(/\/$/, '')}/${objectKey}`,
    dir: objectKey.split('/').slice(0, 2).join('/'),
  });
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
const KEY_RE = /^upweb\/[A-Za-z0-9._\/-]+$/;
function validMpKey(key) {
  return typeof key === 'string' && key.length <= 512 && KEY_RE.test(key) && !key.includes('..');
}
function encodeKeyPath(key) {
  return key.split('/').map(encodeURIComponent).join('/');
}

// 服务端签名直调 OSS（init/complete/abort），V1 Header 签名 + 签名自愈重试
async function ossRequest(method, key, subResource, contentType, bodyText) {
  const bucket = getEnv('OSS_BUCKET');
  const endpoint = getEnv('OSS_ENDPOINT');
  const url = `https://${bucket}.${endpoint}/${encodeKeyPath(key)}${subResource}`;
  const date = new Date().toUTCString();
  const canonicalizedResource = `/${bucket}/${key}${subResource}`;
  const myStringToSign = `${method}\n\n${contentType || ''}\n\nx-oss-date:${date}\n${canonicalizedResource}`;
  const headers = {
    'x-oss-date': date,
    Authorization: `OSS ${getEnv('OSS_ACCESS_KEY_ID')}:${await hmacSha1Base64(getEnv('OSS_ACCESS_KEY_SECRET'), myStringToSign)}`,
  };
  if (contentType) headers['Content-Type'] = contentType;
  let r = await fetch(url, { method, headers, body: bodyText || undefined });
  let xml = await r.text();
  if (!r.ok) {
    const code = (xml.match(/<Code>([^<]+)<\/Code>/) || [])[1] || r.status;
    const ossString = (xml.match(/<StringToSign>([\s\S]*?)<\/StringToSign>/) || [])[1];
    if (code === 'SignatureDoesNotMatch' && ossString) {
      const ossStr = xmlUnescape(ossString);
      headers.Authorization = `OSS ${getEnv('OSS_ACCESS_KEY_ID')}:${await hmacSha1Base64(getEnv('OSS_ACCESS_KEY_SECRET'), ossStr)}`;
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
  let body;
  try { body = await request.json(); } catch { return jsonResponse({ error: '请求体必须是 JSON' }, 400); }
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
      const key = makeObjectKey(body.filename || 'file.bin');
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
      // ListParts 核验 OSS 端实际分片数与总字节数，超声明值自动 Abort 清理
      let marker = 0, actualCount = 0, actualBytes = 0;
      for (let guard = 0; guard < 20; guard++) {
        const sub = marker
          ? `?part-number-marker=${marker}&uploadId=${encodeURIComponent(uploadId)}`
          : `?uploadId=${encodeURIComponent(uploadId)}`;
        const lp = await ossRequest('GET', key, sub, '', null);
        const sizes = [...lp.matchAll(/<Size>(\d+)<\/Size>/g)];
        actualCount += sizes.length;
        actualBytes += sizes.reduce((sum, x) => sum + parseInt(x[1], 10), 0);
        const truncated = /<IsTruncated>true<\/IsTruncated>/.test(lp);
        const next = (lp.match(/<NextPartNumberMarker>(\d+)<\/NextPartNumberMarker>/) || [])[1];
        if (!truncated || !next) break;
        marker = parseInt(next, 10);
      }
      if (actualCount > mp.m || actualBytes > mp.s) {
        await ossRequest('DELETE', key, `?uploadId=${encodeURIComponent(uploadId)}`, '', null).catch(() => {});
        return jsonResponse({ error: '实际上传内容超出声明大小，会话已清理' }, 400);
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
      await ossRequest('POST', key, `?uploadId=${encodeURIComponent(uploadId)}`, 'application/xml', xmlBody);
      return jsonResponse({ ok: true, key, url: `${getEnv('PUBLIC_URL_BASE').replace(/\/$/, '')}/${encodeKeyPath(key)}`, dir: key.split('/').slice(0, 2).join('/') });
    }

    if (action === 'abort') {
      const key = String(body.key || '');
      const uploadId = String(body.uploadId || '');
      if (!validMpKey(key) || !uploadId) return jsonResponse({ error: '参数非法' }, 400);
      const mp = await mpSession(body, key, uploadId);
      if (!mp) return rejectSession();
      await ossRequest('DELETE', key, `?uploadId=${encodeURIComponent(uploadId)}`, '', null);
      return jsonResponse({ ok: true });
    }

    return jsonResponse({ error: '未知 action（支持 init/part/complete/abort）' }, 400);
  } catch (e) {
    return jsonResponse({ error: e.message }, 502);
  }
}

async function handleRequest(request) {
  const url = new URL(request.url);
  if (request.method === 'OPTIONS') return new Response(null, { headers: CORS });
  if (url.pathname === '/api/sign' && request.method === 'POST') return handleSign(request);
  if (url.pathname === '/api/list' && request.method === 'POST') return handleList(request);
  if (url.pathname === '/api/delete' && request.method === 'POST') return handleDelete(request);
  if (url.pathname === '/api/multipart' && request.method === 'POST') return handleMultipart(request);
  return jsonResponse({ error: 'Not Found. 接口：POST /api/sign、POST /api/list、POST /api/delete、POST /api/multipart。' }, 404);
}

// ESA 边缘函数入口（Service Worker 风格）
addEventListener('fetch', event => {
  event.respondWith(handleRequest(event.request));
});
