// ============================================================
// OSS 分片上传函数 —— EdgeOne Pages Functions / Cloudflare Pages Functions 通用版
// 路由：POST /api/multipart
// 原理：大文件走 OSS Multipart Upload（分片上传）：
//   1) action=init     服务端调用 InitiateMultipartUpload，返回 uploadId + key
//   2) action=part     服务端为单个分片签发「预签名 URL」（V1 URL 签名），
//                      浏览器拿 URL 直传该分片到 OSS，本函数不接触文件内容
//   3) action=complete 服务端调用 CompleteMultipartUpload 合并分片
//   4) action=abort    服务端调用 AbortMultipartUpload 清理残留分片
// 为什么能治「慢网速超过 10 分钟」：
//   每个分片的预签名 URL 都是「即签即传」、各自独立计时（默认 1 小时有效），
//   总上传时长不受任何单一签名有效期限制；失败的分片可单独重签重传，
//   已传成功的分片保存在 OSS 服务端，支持断点续传。
// 安全：密钥不出服务端；每个 action 都校验 UPLOAD_PASSWORD；
//       key 强制 upweb/ 前缀白名单，杜绝越权操作其他对象。
// 环境变量：与 sign.js 相同，新增（可选）：
//   PART_SIZE_MB  分片大小，默认 10（MB），范围 5~100
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

function xmlUnescape(s) {
  return s
    .replace(/&lt;/g, '<')
    .replace(/&gt;/g, '>')
    .replace(/&quot;/g, '"')
    .replace(/&#39;|&apos;/g, "'")
    .replace(/&amp;/g, '&');
}

function xmlEscape(s) {
  return String(s)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

const IMG_EXTS = ['jpg', 'jpeg', 'png', 'gif', 'webp', 'svg', 'avif', 'bmp', 'ico', 'tiff'];
const VIDEO_EXTS = ['mp4', 'webm', 'mov', 'mkv', 'm4v', 'avi', 'flv', 'ts'];

// 与 sign.js 同一套目录归类规则，保证两种上传方式落到相同路径
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

// key 白名单校验：只允许 upweb/ 前缀，禁止 ..
function validKey(key) {
  return typeof key === 'string' && key.startsWith('upweb/') && !key.includes('..');
}

// 对象键逐段编码（保留 / 分隔符），用于拼接 URL 路径
function encodeKeyPath(key) {
  return key.split('/').map(encodeURIComponent).join('/');
}

// ------------------------------------------------------------
// 服务端签名直调 OSS（init / complete / abort），V1 Header 签名
// + 签名自愈：若 OSS 返回 SignatureDoesNotMatch，用其错误 XML 中
//   <StringToSign>（OSS 按实际收到的请求算出的待签串）重签重试一次，
//   可自动适应边缘运行时对请求头的任何改写。
// ------------------------------------------------------------
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
        throw new Error(
          `OSS ${method} 请求失败：` + code2 +
          '（已按 OSS 签名串重试仍失败）｜OSS期望[' + ossStr.replace(/\n/g, '⏎') +
          ']｜我方[' + myStringToSign.replace(/\n/g, '⏎') + ']'
        );
      }
    } else {
      throw new Error(`OSS ${method} 请求失败：` + code);
    }
  }
  return xml;
}

// ------------------------------------------------------------
// 为单个分片签发「预签名 URL」（V1 URL 签名，浏览器直传用）
// StringToSign = PUT\n\n{Content-Type}\n{Expires}\n/{bucket}/{key}?partNumber={n}&uploadId={id}
// （子资源按名称排序：partNumber < uploadId）
// 有效期 1 小时；每个分片即签即传，慢网速总时长不设限。
// ------------------------------------------------------------
async function signPartUrl(env, key, uploadId, partNumber, mime) {
  const bucket = env.OSS_BUCKET;
  const expires = Math.floor(Date.now() / 1000) + 3600;
  const stringToSign = `PUT\n\n${mime}\n${expires}\n/${bucket}/${key}?partNumber=${partNumber}&uploadId=${uploadId}`;
  const signature = await hmacSha1Base64(env.OSS_ACCESS_KEY_SECRET, stringToSign);

  const url = `https://${bucket}.${env.OSS_ENDPOINT}/${encodeKeyPath(key)}`
    + `?partNumber=${partNumber}&uploadId=${encodeURIComponent(uploadId)}`
    + `&OSSAccessKeyId=${encodeURIComponent(env.OSS_ACCESS_KEY_ID)}`
    + `&Expires=${expires}&Signature=${encodeURIComponent(signature)}`;
  return url;
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

  // 所有分片操作都校验上传密码
  if (env.UPLOAD_PASSWORD && body.password !== env.UPLOAD_PASSWORD) {
    return jsonResponse({ error: '上传密码错误' }, 401);
  }

  const maxMB = parseInt(env.MAX_SIZE_MB, 10) || 100;
  const maxSize = maxMB * 1024 * 1024;
  let partMB = parseInt(env.PART_SIZE_MB, 10) || 10;
  if (partMB < 5) partMB = 5;
  if (partMB > 100) partMB = 100;
  const partSize = partMB * 1024 * 1024;

  const action = String(body.action || '');

  try {
    // ---------- 1) 初始化分片上传 ----------
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

      return jsonResponse({
        key,
        uploadId,
        partSize,
        dir: key.split('/').slice(0, 2).join('/'),
      });
    }

    // ---------- 2) 为单个分片签发预签名 URL ----------
    if (action === 'part') {
      const key = String(body.key || '');
      const uploadId = String(body.uploadId || '');
      const partNumber = parseInt(body.partNumber, 10);
      if (!validKey(key) || !uploadId) {
        return jsonResponse({ error: '参数非法' }, 400);
      }
      if (!Number.isInteger(partNumber) || partNumber < 1 || partNumber > 10000) {
        return jsonResponse({ error: 'partNumber 须在 1~10000 之间' }, 400);
      }
      const mime = String(body.mime || 'application/octet-stream').slice(0, 100) || 'application/octet-stream';
      const url = await signPartUrl(env, key, uploadId, partNumber, mime);
      return jsonResponse({ url, expiresIn: 3600 });
    }

    // ---------- 3) 合并分片 ----------
    if (action === 'complete') {
      const key = String(body.key || '');
      const uploadId = String(body.uploadId || '');
      const parts = Array.isArray(body.parts) ? body.parts : [];
      if (!validKey(key) || !uploadId || parts.length === 0 || parts.length > 10000) {
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

      return jsonResponse({
        ok: true,
        key,
        url: `${env.PUBLIC_URL_BASE.replace(/\/$/, '')}/${key}`,
        dir: key.split('/').slice(0, 2).join('/'),
      });
    }

    // ---------- 4) 取消分片上传（清理残留分片，避免产生存储费） ----------
    if (action === 'abort') {
      const key = String(body.key || '');
      const uploadId = String(body.uploadId || '');
      if (!validKey(key) || !uploadId) {
        return jsonResponse({ error: '参数非法' }, 400);
      }
      await ossRequest(env, 'DELETE', key, `?uploadId=${encodeURIComponent(uploadId)}`, '', null);
      return jsonResponse({ ok: true });
    }

    return jsonResponse({ error: '未知 action（支持 init/part/complete/abort）' }, 400);
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
