// ============================================================
// OSS 直传签名 —— 阿里云 ESA 边缘函数（Edge Routine）版
// 路由：POST /api/sign
// 部署：ESA 控制台 → 边缘函数 → 新建函数 → 粘贴本文件 → 发布 →
//       在「函数路由/域名关联」中把你的管理站点域名关联到本函数
// 注意：ESA 边缘函数若不支持控制台环境变量，直接在下方 CONFIG 里填写即可
//       （填了 CONFIG 的代码文件不要再提交到公开仓库！）
// 前端 index.html 可部署在 ESA Pages 或任何静态托管上，
// 本函数已放开 /api/sign 的 CORS。
// ============================================================

// 如果 ESA 没有配环境变量的入口，就在这里直接填（优先级高于环境变量）：
const CONFIG = {
  OSS_ACCESS_KEY_ID: '',
  OSS_ACCESS_KEY_SECRET: '',
  OSS_BUCKET: '',
  OSS_ENDPOINT: '',       // 如 oss-cn-hongkong.aliyuncs.com
  PUBLIC_URL_BASE: '',    // 如 https://img.example.com（你的 CF 免流域名）
  UPLOAD_PASSWORD: '',    // 可选，留空表示不需要上传密码
  MAX_SIZE_MB: '',        // 可选，默认 10
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

function makeObjectKey(filename) {
  const ext = (filename.split('.').pop() || 'bin').toLowerCase().replace(/[^a-z0-9]/g, '').slice(0, 8) || 'bin';
  const d = new Date();
  const datePath = d.getFullYear() + String(d.getMonth() + 1).padStart(2, '0') + String(d.getDate()).padStart(2, '0');
  const rand = crypto.randomUUID().replace(/-/g, '');
  return `img/${datePath}/${rand}.${ext}`;
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
async function listObjects(token) {
  const bucket = getEnv('OSS_BUCKET');
  const endpoint = getEnv('OSS_ENDPOINT');
  const params = new URLSearchParams({ 'list-type': '2', prefix: 'img/', 'max-keys': '60' });
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
    files.push({ key: xmlUnescape(m[1]), time: m[2], size: parseInt(m[3], 10), url: getEnv('PUBLIC_URL_BASE').replace(/\/$/, '') + '/' + m[1] });
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
  let body;
  try { body = await request.json(); } catch { return jsonResponse({ error: '请求体必须是 JSON' }, 400); }
  const pwd = getEnv('UPLOAD_PASSWORD');
  if (pwd && body.password !== pwd) {
    return jsonResponse({ error: '上传密码错误' }, 401);
  }
  try {
    return jsonResponse(await listObjects(body.token || ''));
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
  let body;
  try { body = await request.json(); } catch { return jsonResponse({ error: '请求体必须是 JSON' }, 400); }
  const pwd = getEnv('UPLOAD_PASSWORD');
  if (pwd && body.password !== pwd) {
    return jsonResponse({ error: '上传密码错误' }, 401);
  }
  const key = String(body.key || '');
  if (!key.startsWith('img/') || key.includes('..')) {
    return jsonResponse({ error: '仅允许删除 img/ 前缀下的文件' }, 400);
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

  let body;
  try { body = await request.json(); } catch { return jsonResponse({ error: '请求体必须是 JSON' }, 400); }

  const pwd = getEnv('UPLOAD_PASSWORD');

  // 密码预检：前端登录门禁专用，只验密码、不生成签名
  if (body.check === true) {
    if (pwd && body.password !== pwd) {
      return jsonResponse({ error: '上传密码错误' }, 401);
    }
    return jsonResponse({ ok: true, needPassword: !!pwd });
  }

  if (pwd && body.password !== pwd) {
    return jsonResponse({ error: '上传密码错误' }, 401);
  }

  const maxSize = (parseInt(getEnv('MAX_SIZE_MB'), 10) || 10) * 1024 * 1024;
  const size = parseInt(body.size, 10) || 0;
  if (size <= 0 || size > maxSize) {
    return jsonResponse({ error: `文件大小超限（上限 ${Math.round(maxSize / 1024 / 1024)}MB）` }, 400);
  }

  const objectKey = makeObjectKey(body.filename || 'image.png');
  const policy = btoa(JSON.stringify({
    expiration: new Date(Date.now() + 5 * 60 * 1000).toISOString(),
    conditions: [['content-length-range', 1, maxSize], ['starts-with', '$key', 'img/']],
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
    },
    url: `${getEnv('PUBLIC_URL_BASE').replace(/\/$/, '')}/${objectKey}`,
  });
}

async function handleRequest(request) {
  const url = new URL(request.url);
  if (request.method === 'OPTIONS') return new Response(null, { headers: CORS });
  if (url.pathname === '/api/sign' && request.method === 'POST') return handleSign(request);
  if (url.pathname === '/api/list' && request.method === 'POST') return handleList(request);
  if (url.pathname === '/api/delete' && request.method === 'POST') return handleDelete(request);
  return jsonResponse({ error: 'Not Found. 接口：POST /api/sign、POST /api/list、POST /api/delete。' }, 404);
}

// ESA 边缘函数入口（Service Worker 风格）
addEventListener('fetch', event => {
  event.respondWith(handleRequest(event.request));
});
