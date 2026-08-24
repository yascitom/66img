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
//   UPLOAD_PASSWORD        （可选）上传密码，设置后前端必须填对才能拿签名
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

// 按扩展名归类目录，生成随机对象键：upweb/img/20260824/a1b2c3....webp
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

  const maxMB = parseInt(env.MAX_SIZE_MB, 10) || 100;
  const maxSize = maxMB * 1024 * 1024;

  // 密码预检：前端登录门禁专用，只验密码、不生成签名（顺带返回大小上限给前端展示）
  if (body.check === true) {
    if (!(await pwdOk(body.password, env.UPLOAD_PASSWORD))) {
      return rejectAuth();
    }
    return jsonResponse({ ok: true, needPassword: !!env.UPLOAD_PASSWORD, maxMB });
  }

  // 上传密码校验（如设置了 UPLOAD_PASSWORD）
  if (!(await pwdOk(body.password, env.UPLOAD_PASSWORD))) {
    return rejectAuth();
  }

  const size = parseInt(body.size, 10) || 0;
  if (size <= 0 || size > maxSize) {
    return jsonResponse({ error: `文件大小超限（上限 ${maxMB}MB）` }, 400);
  }

  const objectKey = makeObjectKey(body.filename || 'file.bin');

  // PostObject Policy：10 分钟有效（大文件上传耗时更长），限制大小和 key 前缀
  const policyObj = {
    expiration: new Date(Date.now() + 10 * 60 * 1000).toISOString(),
    conditions: [
      ['content-length-range', 1, maxSize],
      ['starts-with', '$key', 'upweb/'],
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
