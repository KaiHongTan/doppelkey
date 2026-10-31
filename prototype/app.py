import os, json, jwt, itsdangerous
r = {}
s = os.environ['JWT_SECRET']
tok = jwt.encode({'sub': 'user1'}, s, algorithm='HS256')
r['pyjwt'] = tok; r['pyjwtVerify'] = jwt.decode(tok, s, algorithms=['HS256'])['sub']
signer = itsdangerous.URLSafeSerializer(os.environ['COOKIE_SECRET'], salt='cookie-session')
cookie = signer.dumps({'user': 'alice'}); r['itsdangerous'] = cookie; r['itsdangerousLoads'] = signer.loads(cookie)['user']
print(json.dumps(r, indent=1))
json.dump(r, open('/tmp/py.results.json', 'w'))
