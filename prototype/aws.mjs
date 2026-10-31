// An unmodified app using the AWS SDK for JavaScript v3. Credentials come from the
// environment as usual. Nothing is sent to AWS: a stub request handler captures the
// signed request so the oracle can verify it the way AWS would.
import { S3Client, PutObjectCommand, GetObjectCommand } from '@aws-sdk/client-s3';
import { getSignedUrl } from '@aws-sdk/s3-request-presigner';
import { DynamoDBClient, ListTablesCommand } from '@aws-sdk/client-dynamodb';
import { Readable } from 'node:stream';
import fs from 'node:fs';
import { createHash } from 'node:crypto';

const captured = [];
const requestHandler = {
  async handle(req) {
    const q = new URLSearchParams(req.query || {}).toString();
    captured.push({
      method: req.method,
      url: `${req.protocol}//${req.hostname}${req.path}${q ? '?' + q : ''}`,
      headers: req.headers,
      bodySha256: createHash('sha256').update(typeof req.body === 'string' ? req.body : Buffer.from(req.body || '')).digest('hex'),
    });
    return { response: { statusCode: 200, headers: { etag: '"x"' }, body: Readable.from([]) } };
  },
};
const results = { errors: {} };
const s3 = new S3Client({ requestHandler });

// 1. A normal signed request (Authorization header)
await s3.send(new PutObjectCommand({ Bucket: 'doppelkey-test', Key: 'hello.txt', Body: 'hello from doppelkey' }));
// 2. A presigned URL (signature in the query string)
results.presignedUrl = await getSignedUrl(s3, new GetObjectCommand({ Bucket: 'doppelkey-test', Key: 'hello.txt' }), { expiresIn: 600 });
results.headerRequests = captured.slice(); // S3 only

// 3. Policy: this key may only sign for S3. Try DynamoDB with the same credentials.
try {
  await new DynamoDBClient({ requestHandler }).send(new ListTablesCommand({}));
  results.dynamodbSigned = true;
} catch (e) { results.errors.dynamodb = e.message; }

results.envSecretSeenByApp = process.env.AWS_SECRET_ACCESS_KEY;
fs.writeFileSync(process.env.OUT || '/tmp/aws.results.json', JSON.stringify(results, null, 2));
console.log('READY', process.pid);
setTimeout(() => {}, 60000); // stay alive so the oracle can scan this process's memory
