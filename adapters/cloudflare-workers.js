// ============================================================
// OSS 直传签名 —— Cloudflare Workers 独立版（Module Worker）
// 路由：POST /api/sign、POST /api/list、POST /api/delete、POST /api/multipart（大文件分片上传）
// 部署：Workers 控制台新建 Worker → 粘贴本文件 → Settings → Variables 配置环境变量
//       （也可直接 wrangler deploy）
// 前端 index.html 可托管在任何地方（CF Pages / EO Pages / 本地），
// 本 Worker 已放开 /api/* 的 CORS。
// 环境变量同 EO 版：OSS_ACCESS_KEY_ID / OSS_ACCESS_KEY_SECRET / OSS_BUCKET /
//                  OSS_ENDPOINT / PUBLIC_URL_BASE / UPLOAD_PASSWORD(可选) /
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
  return jsonResponse({ error: '上传密码错误' }, 401);
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
  let body;
  try { body = await request.json(); } catch { return jsonResponse({ error: '请求体必须是 JSON' }, 400); }
  if (!(await pwdOk(body.password, env.UPLOAD_PASSWORD))) {
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
  let body;
  try { body = await request.json(); } catch { return jsonResponse({ error: '请求体必须是 JSON' }, 400); }
  if (!(await pwdOk(body.password, env.UPLOAD_PASSWORD))) {
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
// key 白名单：upweb/ 前缀 + 安全字符集（字母数字 . _ - /），禁 .. 与引号/尖括号等可注入字符
const KEY_RE = /^upweb\/[A-Za-z0-9._\/-]+$/;
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
  let body;
  try { body = await request.json(); } catch { return jsonResponse({ error: '请求体必须是 JSON' }, 400); }
  if (!(await pwdOk(body.password, env.UPLOAD_PASSWORD))) {
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
      const key = makeObjectKey(body.filename || 'file.bin');
      const xml = await ossRequest(env, 'POST', key, '?uploads', mime, null);
      const uploadId = (xml.match(/<UploadId>([^<]+)<\/UploadId>/) || [])[1];
      if (!uploadId) throw new Error('OSS 未返回 UploadId');
      return jsonResponse({ key, uploadId, partSize, dir: key.split('/').slice(0, 2).join('/') });
    }

    if (action === 'part') {
      const key = String(body.key || '');
      const uploadId = String(body.uploadId || '');
      const partNumber = parseInt(body.partNumber, 10);
      if (!validMpKey(key) || !uploadId) return jsonResponse({ error: '参数非法' }, 400);
      if (!Number.isInteger(partNumber) || partNumber < 1 || partNumber > 10000) {
        return jsonResponse({ error: 'partNumber 须在 1~10000 之间' }, 400);
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

  let body;
  try { body = await request.json(); } catch { return jsonResponse({ error: '请求体必须是 JSON' }, 400); }

  const maxMB = parseInt(env.MAX_SIZE_MB, 10) || 100;
  const maxSize = maxMB * 1024 * 1024;

  // 密码预检：前端登录门禁专用，只验密码、不生成签名（顺带返回大小上限）
  if (body.check === true) {
    if (!(await pwdOk(body.password, env.UPLOAD_PASSWORD))) {
      return rejectAuth();
    }
    return jsonResponse({ ok: true, needPassword: !!env.UPLOAD_PASSWORD, maxMB });
  }

  if (!(await pwdOk(body.password, env.UPLOAD_PASSWORD))) {
    return rejectAuth();
  }

  const size = parseInt(body.size, 10) || 0;
  if (size <= 0 || size > maxSize) {
    return jsonResponse({ error: `文件大小超限（上限 ${maxMB}MB）` }, 400);
  }

  const objectKey = makeObjectKey(body.filename || 'file.bin');
  const policy = btoa(JSON.stringify({
    expiration: new Date(Date.now() + 10 * 60 * 1000).toISOString(),
    conditions: [['content-length-range', 1, maxSize], ['starts-with', '$key', 'upweb/']],
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
    },
    url: `${env.PUBLIC_URL_BASE.replace(/\/$/, '')}/${objectKey}`,
    dir: objectKey.split('/').slice(0, 2).join('/'),
  });
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    if (request.method === 'OPTIONS') return new Response(null, { headers: CORS });
    if (url.pathname === '/api/sign' && request.method === 'POST') return handleSign(request, env);
    if (url.pathname === '/api/list' && request.method === 'POST') return handleList(request, env);
    if (url.pathname === '/api/delete' && request.method === 'POST') return handleDelete(request, env);
    if (url.pathname === '/api/multipart' && request.method === 'POST') return handleMultipart(request, env);
    return jsonResponse({ error: 'Not Found. 接口：POST /api/sign、POST /api/list、POST /api/delete、POST /api/multipart。' }, 404);
  },
};
