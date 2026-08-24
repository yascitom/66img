// ============================================================
// OSS 文件列表函数 —— EdgeOne Pages Functions / Cloudflare Pages Functions 通用版
// 路由：POST /api/list
// 原理：服务端用 AccessKey 签名调用 OSS ListObjectsV2，返回文件列表。
//       仅允许列出 img/ 前缀，密钥不出服务端。
// 请求体：{ password, token? }   token 为分页游标（首次不传）
// 返回：{ files:[{key,size,time,url}], nextToken, truncated }
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

// OSS ListObjectsV2（GET Bucket），V1 签名：
// StringToSign = GET\n\n\n<Date>\n/<bucket>/?list-type=2
async function listObjects(env, token) {
  const bucket = env.OSS_BUCKET;
  const endpoint = env.OSS_ENDPOINT;

  const params = new URLSearchParams({
    'list-type': '2',
    prefix: 'img/',
    'max-keys': '60',
  });
  if (token) params.set('continuation-token', token);

  const date = new Date().toUTCString();
  const stringToSign = 'GET\n\n\n' + date + '\n/' + bucket + '/?list-type=2';
  const signature = await hmacSha1Base64(env.OSS_ACCESS_KEY_SECRET, stringToSign);

  const r = await fetch(`https://${bucket}.${endpoint}/?${params.toString()}`, {
    headers: {
      Date: date,
      Authorization: `OSS ${env.OSS_ACCESS_KEY_ID}:${signature}`,
    },
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
    files.push({
      key: m[1],
      time: m[2],
      size: parseInt(m[3], 10),
      url: env.PUBLIC_URL_BASE.replace(/\/$/, '') + '/' + m[1],
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

  let body;
  try {
    body = await request.json();
  } catch {
    return jsonResponse({ error: '请求体必须是 JSON' }, 400);
  }

  if (env.UPLOAD_PASSWORD && body.password !== env.UPLOAD_PASSWORD) {
    return jsonResponse({ error: '上传密码错误' }, 401);
  }

  try {
    const result = await listObjects(env, body.token || '');
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
