// ============================================================
// OSS 直传签名函数 —— EdgeOne Pages Functions / Cloudflare Pages Functions 通用版
// 路由：POST /api/sign
// 原理：生成 OSS PostObject 的 Policy + 签名，浏览器拿到后直传 OSS，
//       本函数不接触图片内容，每次上传仅调用 1 次。
// 环境变量（在平台控制台配置，切勿写进代码仓库）：
//   OSS_ACCESS_KEY_ID      阿里云 OSS AccessKeyId（建议用仅授权该桶的 RAM 子账号）
//   OSS_ACCESS_KEY_SECRET  对应的 AccessKeySecret
//   OSS_BUCKET             Bucket 名称，如 my-img
//   OSS_ENDPOINT           Bucket 地域节点，如 oss-cn-hongkong.aliyuncs.com
//   PUBLIC_URL_BASE        图片访问域名（CF 免流域名），如 https://img.example.com
//   UPLOAD_PASSWORD        （可选）上传密码，设置后前端必须填对才能拿签名
//   MAX_SIZE_MB            （可选）单文件上限，默认 10
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

// 生成随机对象键：img/20260124/a1b2c3d4e5f6....webp
function makeObjectKey(filename) {
  const ext = (filename.split('.').pop() || 'bin').toLowerCase().replace(/[^a-z0-9]/g, '').slice(0, 8) || 'bin';
  const d = new Date();
  const datePath = d.getFullYear() + String(d.getMonth() + 1).padStart(2, '0') + String(d.getDate()).padStart(2, '0');
  const rand = crypto.randomUUID().replace(/-/g, '');
  return `img/${datePath}/${rand}.${ext}`;
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

  // 密码预检：前端登录门禁专用，只验密码、不生成签名
  if (body.check === true) {
    if (env.UPLOAD_PASSWORD && body.password !== env.UPLOAD_PASSWORD) {
      return jsonResponse({ error: '上传密码错误' }, 401);
    }
    return jsonResponse({ ok: true, needPassword: !!env.UPLOAD_PASSWORD });
  }

  // 上传密码校验（如设置了 UPLOAD_PASSWORD）
  if (env.UPLOAD_PASSWORD && body.password !== env.UPLOAD_PASSWORD) {
    return jsonResponse({ error: '上传密码错误' }, 401);
  }

  const maxSize = (parseInt(env.MAX_SIZE_MB, 10) || 10) * 1024 * 1024;
  const size = parseInt(body.size, 10) || 0;
  if (size <= 0 || size > maxSize) {
    return jsonResponse({ error: `文件大小超限（上限 ${Math.round(maxSize / 1024 / 1024)}MB）` }, 400);
  }

  const objectKey = makeObjectKey(body.filename || 'image.png');

  // PostObject Policy：5 分钟有效，限制大小和 key 前缀
  const policyObj = {
    expiration: new Date(Date.now() + 5 * 60 * 1000).toISOString(),
    conditions: [
      ['content-length-range', 1, maxSize],
      ['starts-with', '$key', 'img/'],
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
    },
    url: `${env.PUBLIC_URL_BASE.replace(/\/$/, '')}/${objectKey}`,
  });
}

// EdgeOne Pages Functions / Cloudflare Pages Functions 入口
export async function onRequestPost(context) {
  return handle(context.request, context.env);
}
export async function onRequest(context) {
  return handle(context.request, context.env);
}
