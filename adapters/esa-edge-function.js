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