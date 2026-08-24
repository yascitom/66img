// ============================================================
// OSS 直传签名 —— Cloudflare Workers 独立版（Module Worker）
// 路由：POST /api/sign
// 部署：Workers 控制台新建 Worker → 粘贴本文件 → Settings → Variables 配置环境变量
//       （也可直接 wrangler deploy）
// 前端 index.html 可托管在任何地方（CF Pages / EO Pages / 本地），
// 本 Worker 已放开 /api/sign 的 CORS。
// 环境变量同 EO 版：OSS_ACCESS_KEY_ID / OSS_ACCESS_KEY_SECRET / OSS_BUCKET /
//                  OSS_ENDPOINT / PUBLIC_URL_BASE / UPLOAD_PASSWORD(可选) / MAX_SIZE_MB(可选)
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

function makeObjectKey(filename) {
  const ext = (filename.split('.').pop() || 'bin').toLowerCase().replace(/[^a-z0-9]/g, '').slice(0, 8) || 'bin';
  const d = new Date();
  const datePath = d.getFullYear() + String(d.getMonth() + 1).padStart(2, '0') + String(d.getDate()).padStart(2, '0');
  const rand = crypto.randomUUID().replace(/-/g, '');
  return `img/${datePath}/${rand}.${ext}`;
}

// OSS ListObjectsV2（GET Bucket），V1 签名。
// 用 x-oss-date 替代 Date 头（边缘运行时受限头会被改写，否则 SignatureDoesNotMatch）
async function listObjects(env, token) {
  const bucket = env.OSS_BUCKET;
  const endpoint = env.OSS_ENDPOINT;
  const params = new URLSearchParams({ 'list-type': '2', prefix: 'img/', 'max-keys': '60' });
  if (token) params.set('continuation-token', token);
  const date = new Date().toUTCString();
  const stringToSign = 'GET\n\n\n\nx-oss-date:' + date + '\n/' + bucket + '/?list-type=2';
  const signature = await hmacSha1Base64(env.OSS_ACCESS_KEY_SECRET, stringToSign);
  const r = await fetch(`https://${bucket}.${endpoint}/?${params.toString()}`, {
    headers: { 'x-oss-date': date, Authorization: `OSS ${env.OSS_ACCESS_KEY_ID}:${signature}` },
  });
  const xml = await r.text();
  if (!r.ok) {
    const code = (xml.match(/<Code>([^<]+)<\/Code>/) || [])[1] || r.status;
    throw new Error('OSS 列表请求失败：' + code);
  }
  const files = [];
  const re = /<Contents>[\s\S]*?<Key>([\s\S]*?)<\/Key>[\s\S]*?<LastModified>([\s\S]*?)<\/LastModified>[\s\S]*?<Size>(\d+)<\/Size>[\s\S]*?<\/Contents>/g;
  let m;
  while ((m = re.exec(xml)) !== null) {
    files.push({ key: m[1], time: m[2], size: parseInt(m[3], 10), url: env.PUBLIC_URL_BASE.replace(/\/$/, '') + '/' + m[1] });
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
  if (env.UPLOAD_PASSWORD && body.password !== env.UPLOAD_PASSWORD) {
    return jsonResponse({ error: '上传密码错误' }, 401);
  }
  try {
    return jsonResponse(await listObjects(env, body.token || ''));
  } catch (e) {
    return jsonResponse({ error: e.message }, 502);
  }
}

// OSS DeleteObject：用 x-oss-date 替代 Date 头
// StringToSign = DELETE\n\n\n\nx-oss-date:<date>\n/<bucket>/<key>
async function deleteObject(env, key) {
  const bucket = env.OSS_BUCKET;
  const endpoint = env.OSS_ENDPOINT;
  const date = new Date().toUTCString();
  const stringToSign = 'DELETE\n\n\n\nx-oss-date:' + date + '\n/' + bucket + '/' + key;
  const signature = await hmacSha1Base64(env.OSS_ACCESS_KEY_SECRET, stringToSign);
  const r = await fetch(`https://${bucket}.${endpoint}/${key.split('/').map(encodeURIComponent).join('/')}`, {
    method: 'DELETE',
    headers: { 'x-oss-date': date, Authorization: `OSS ${env.OSS_ACCESS_KEY_ID}:${signature}` },
  });
  if (!r.ok && r.status !== 204) {
    const xml = await r.text();
    const code = (xml.match(/<Code>([^<]+)<\/Code>/) || [])[1] || r.status;
    throw new Error('OSS 删除失败：' + code);
  }
}

async function handleDelete(request, env) {
  const required = ['OSS_ACCESS_KEY_ID', 'OSS_ACCESS_KEY_SECRET', 'OSS_BUCKET', 'OSS_ENDPOINT'];
  for (const k of required) {
    if (!env[k]) return jsonResponse({ error: `服务端缺少环境变量 ${k}` }, 500);
  }
  let body;
  try { body = await request.json(); } catch { return jsonResponse({ error: '请求体必须是 JSON' }, 400); }
  if (env.UPLOAD_PASSWORD && body.password !== env.UPLOAD_PASSWORD) {
    return jsonResponse({ error: '上传密码错误' }, 401);
  }
  const key = String(body.key || '');
  if (!key.startsWith('img/') || key.includes('..')) {
    return jsonResponse({ error: '仅允许删除 img/ 前缀下的文件' }, 400);
  }
  try {
    await deleteObject(env, key);
    return jsonResponse({ ok: true, key });
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

  // 密码预检：前端登录门禁专用，只验密码、不生成签名
  if (body.check === true) {
    if (env.UPLOAD_PASSWORD && body.password !== env.UPLOAD_PASSWORD) {
      return jsonResponse({ error: '上传密码错误' }, 401);
    }
    return jsonResponse({ ok: true, needPassword: !!env.UPLOAD_PASSWORD });
  }

  if (env.UPLOAD_PASSWORD && body.password !== env.UPLOAD_PASSWORD) {
    return jsonResponse({ error: '上传密码错误' }, 401);
  }

  const maxSize = (parseInt(env.MAX_SIZE_MB, 10) || 10) * 1024 * 1024;
  const size = parseInt(body.size, 10) || 0;
  if (size <= 0 || size > maxSize) {
    return jsonResponse({ error: `文件大小超限（上限 ${Math.round(maxSize / 1024 / 1024)}MB）` }, 400);
  }

  const objectKey = makeObjectKey(body.filename || 'image.png');
  const policy = btoa(JSON.stringify({
    expiration: new Date(Date.now() + 5 * 60 * 1000).toISOString(),
    conditions: [['content-length-range', 1, maxSize], ['starts-with', '$key', 'img/']],
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
  });
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    if (request.method === 'OPTIONS') return new Response(null, { headers: CORS });
    if (url.pathname === '/api/sign' && request.method === 'POST') return handleSign(request, env);
    if (url.pathname === '/api/list' && request.method === 'POST') return handleList(request, env);
    if (url.pathname === '/api/delete' && request.method === 'POST') return handleDelete(request, env);
    return jsonResponse({ error: 'Not Found. 接口：POST /api/sign、POST /api/list、POST /api/delete。' }, 404);
  },
};
