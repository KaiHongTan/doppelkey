# An unmodified app using boto3. Credentials come from the environment as usual.
# Nothing is sent to AWS: a before-send hook captures the signed request.
import json, os, sys, time, hashlib
import boto3
from botocore.awsrequest import AWSResponse

captured = []
class _Raw:
    def stream(self, **kw): yield b''
    def read(self, *a, **kw): return b''
def capture(request, **kw):
    body = request.body or b''
    body = body.encode() if isinstance(body, str) else (body.read() if hasattr(body, 'read') else bytes(body))
    captured.append({'method': request.method, 'url': request.url,
                     'headers': {k: (v.decode() if isinstance(v, bytes) else v) for k, v in request.headers.items()},
                     'bodySha256': hashlib.sha256(body).hexdigest()})
    return AWSResponse(request.url, 200, {'ETag': '"x"'}, _Raw())

s3 = boto3.client('s3')
s3.meta.events.register('before-send.s3.*', capture)
results = {'errors': {}}
s3.put_object(Bucket='doppelkey-test', Key='hello.txt', Body=b'hello from doppelkey')
results['presignedUrl'] = s3.generate_presigned_url('get_object', Params={'Bucket': 'doppelkey-test', 'Key': 'hello.txt'}, ExpiresIn=600)
results['headerRequests'] = captured
try:
    ddb = boto3.client('dynamodb')
    ddb.meta.events.register('before-send.dynamodb.*', capture)
    ddb.list_tables()
    results['dynamodbSigned'] = True
except Exception as e:
    results['errors']['dynamodb'] = str(e)[:160]
results['envSecretSeenByApp'] = os.environ['AWS_SECRET_ACCESS_KEY']
json.dump(results, open(os.environ.get('OUT', '/tmp/aws_py.results.json'), 'w'), indent=2)
print('READY', os.getpid(), flush=True)
time.sleep(60)
