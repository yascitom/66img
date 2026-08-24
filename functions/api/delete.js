// ============================================================
// OSS 文件删除函数 —— EdgeOne Pages Functions / Cloudflare Pages Functions 通用版
// 路由：POST /api/delete
// 原理：服务端用 AccessKey 签名调用 OSS DeleteObject，仅允许删除 img/ 前缀。
// 请求体：{ password, key }
// 环境变量与 sign.js 相同。RAM 子账号需授予 oss:DeleteObject 权限。
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

// OSS DeleteObject。使用 x-oss-date 替代 Date 头（边缘运行时会改写 Date），
// StringToSign = DELETE\n\n\n\nx-oss-date:<date>\n/<bucket>/<key>
//
// 自愈机制同 list.js：签名被拒时用 OSS 返回的 <StringToSign> 重签重试一次。
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
        throw new Error(
          'OSS 删除失败：' + code2 +
          '（已按 OSS 签名串重试仍失败）｜OSS期望[' + ossStr.replace(/\n/g, '⏎') +
          ']｜我方[' + myStringToSign.replace(/\n/g, '⏎') + ']'
        );
      }
    } else {
      throw new Error('OSS 删除失败：' + code);
    }
  }
}

async function handle(request, env) {
  if (request.method !== 'POST') {
    return jsonResponse({ error: 'Method Not Allowed' }, 405);
  }

  const required = ['OSS_ACCESS_KEY_ID', 'OSS_ACCESS_KEY_SECRET', 'OSS_BUCKET', 'OSS_ENDPOINT'];
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

// EdgeOne Pages Functions / Cloudflare Pages Functions 入口
export async function onRequestPost(context) {
  return handle(context.request, context.env);
}
export async function onRequest(context) {
  return handle(context.request, context.env);
}
