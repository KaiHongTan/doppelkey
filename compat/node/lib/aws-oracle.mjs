// Plays AWS: rebuilds the SigV4 (or SigV2) canonical request and checks the signature with the
// real secret, the way AWS does.
import crypto from 'node:crypto';

const hmac = (k, d) => crypto.createHmac('sha256', k).update(d).digest();
const sha = (d) => crypto.createHash('sha256').update(d).digest('hex');
const enc = (s) => encodeURIComponent(s).replace(/[!'()*]/g, (c) => '%' + c.charCodeAt(0).toString(16).toUpperCase());

export function signingKeys(secret, date, region, service) {
  const kDate = hmac(Buffer.concat([Buffer.from('AWS4'), Buffer.from(secret)]), date), kRegion = hmac(kDate, region), kService = hmac(kRegion, service);
  return { kDate, kRegion, kService, kSigning: hmac(kService, 'aws4_request') };
}

export function verifyAws(secret, { method, url, headers = {}, bodySha256 }) {
  const u = new URL(url);
  if (u.searchParams.has('AWSAccessKeyId')) {
    const bucket = u.hostname.split('.s3')[0];
    const sts = `${method}\n\n\n${u.searchParams.get('Expires')}\n/${bucket}${u.pathname}`;
    return { ok: crypto.createHmac('sha1', secret).update(sts).digest('base64') === u.searchParams.get('Signature'), scope: 'sigv2', keys: {} };
  }
  const h = Object.fromEntries(Object.entries(headers).map(([k, x]) => [k.toLowerCase(), String(x)]));
  if (!h.host) h.host = u.host;
  let cred, signed, sig, amzDate, payload;
  const params = [...u.searchParams.entries()];
  if (h.authorization) {
    const m = h.authorization.match(/^AWS4-HMAC-SHA256 Credential=([^,]+), ?SignedHeaders=([^,]+), ?Signature=([0-9a-f]+)$/);
    if (!m) return { ok: false, why: 'unparseable Authorization header' };
    [, cred, signed, sig] = m; amzDate = h['x-amz-date']; payload = h['x-amz-content-sha256'] || bodySha256;
    if (h['x-amz-content-sha256'] && h['x-amz-content-sha256'] !== bodySha256 && !h['x-amz-content-sha256'].includes('UNSIGNED-PAYLOAD')) return { ok: false, why: 'body hash mismatch' };
  } else {
    const q = Object.fromEntries(params);
    cred = q['X-Amz-Credential']; signed = q['X-Amz-SignedHeaders']; sig = q['X-Amz-Signature']; amzDate = q['X-Amz-Date']; payload = 'UNSIGNED-PAYLOAD';
  }
  const [akid, date, region, service] = cred.split('/');
  const query = params.filter(([k]) => k !== 'X-Amz-Signature').map(([k, x]) => [enc(k), enc(x)]).sort((a, b) => (a[0] < b[0] ? -1 : a[0] > b[0] ? 1 : a[1] < b[1] ? -1 : 1)).map(([k, x]) => `${k}=${x}`).join('&');
  const names = signed.split(';');
  const canon = [method, u.pathname, query, names.map((n) => `${n}:${h[n].trim().replace(/\s+/g, ' ')}\n`).join(''), signed, payload].join('\n');
  const scope = `${date}/${region}/${service}/aws4_request`;
  const sts = ['AWS4-HMAC-SHA256', amzDate, scope, sha(canon)].join('\n');
  const keys = signingKeys(secret, date, region, service);
  return { ok: hmac(keys.kSigning, sts).toString('hex') === sig, akid, scope, keys };
}
