// aws_oracle.mjs: plays AWS. Run WITHOUT the shim. Holds the real secret and checks every
// signature from a results file by rebuilding the SigV4 canonical request, as AWS does.
// Usage: node aws_oracle.mjs <results.json>   -> prints checks + writes /tmp/aws.needles (hex, one per line)
import fs from 'node:fs';
import crypto from 'node:crypto';
const v = JSON.parse(fs.readFileSync('./vault.json', 'utf8'));
const SECRET = Object.values(v).find((x) => x.profile === 'aws-sigv4').key;
const r = JSON.parse(fs.readFileSync(process.argv[2], 'utf8'));

const hmac = (k, d) => crypto.createHmac('sha256', k).update(d).digest();
const sha = (d) => crypto.createHash('sha256').update(d).digest('hex');
const enc = (s) => encodeURIComponent(s).replace(/[!'()*]/g, (c) => '%' + c.charCodeAt(0).toString(16).toUpperCase());
function signingKeys(date, region, service) {
  const kDate = hmac('AWS4' + SECRET, date), kRegion = hmac(kDate, region), kService = hmac(kRegion, service);
  return { kDate, kRegion, kService, kSigning: hmac(kService, 'aws4_request') };
}
function verify({ method, url, headers, bodySha256 }) {
  const u = new URL(url);
  if (u.searchParams.has('AWSAccessKeyId')) {
    // Legacy SigV2 query auth: base64(HMAC-SHA1(secret, "GET\n\n\n<Expires>\n/<bucket>/<key>"))
    const bucket = u.hostname.split('.s3')[0];
    const sts = `${method}\n\n\n${u.searchParams.get('Expires')}\n/${bucket}${u.pathname}`;
    return { ok: crypto.createHmac('sha1', SECRET).update(sts).digest('base64') === u.searchParams.get('Signature'), scope: 'sigv2', keys: {} };
  }
  const h = Object.fromEntries(Object.entries(headers).map(([k, x]) => [k.toLowerCase(), String(x)]));
  if (!h.host) h.host = u.host;
  let cred, signed, sig, amzDate, payload;
  const params = [...u.searchParams.entries()];
  if (h.authorization) {
    const m = h.authorization.match(/^AWS4-HMAC-SHA256 Credential=([^,]+), ?SignedHeaders=([^,]+), ?Signature=([0-9a-f]+)$/);
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
  const keys = signingKeys(date, region, service);
  const expected = hmac(keys.kSigning, sts).toString('hex');
  return { ok: expected === sig, akid, scope, keys };
}

const all = [...r.headerRequests.map((x) => ({ kind: 'header', ...x })), { kind: 'presigned', method: 'GET', url: r.presignedUrl, headers: {} }];
const out = { signaturesValidUnderRealKey: [], scopes: [] };
const needles = new Set([Buffer.from(SECRET).toString('hex')]);
for (const req of all) {
  const res = verify(req);
  out.signaturesValidUnderRealKey.push(`${req.kind}: ${res.ok}`);
  out.scopes.push(res.scope);
  for (const k of Object.values(res.keys || {})) needles.add(k.toString('hex'));
}
out.dynamodbRefused = r.errors.dynamodb || 'NOT refused';
out.secretSeenByApp = r.envSecretSeenByApp === SECRET ? 'REAL SECRET' : r.envSecretSeenByApp;
fs.writeFileSync('/tmp/aws.needles', [...needles].join('\n'));
console.log(JSON.stringify(out, null, 2));
