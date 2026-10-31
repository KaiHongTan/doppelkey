import os, django
from django.conf import settings
settings.configure(SECRET_KEY=os.environ['COOKIE_SECRET'])
from django.core import signing
v = signing.dumps({'user': 'alice'}); print('django signed:', v)
print('django loads:', signing.loads(v)['user'])
open('/tmp/dj.txt','w').write(v)
