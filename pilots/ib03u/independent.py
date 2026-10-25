"""Independent Python binary encoder + OpenSSL Ed25519 validation of pinned fixtures."""
import hashlib,hmac,json,re,subprocess,tempfile
from pathlib import Path
d=json.loads((Path(__file__).parent/'vectors.json').read_text(encoding='utf-8'))
A=[('kid','id'),('keyEpoch','u64'),('nonce','hex16'),('issuedAt','u64'),('expiresAt','u64'),('audience','audience'),('message','utf8'),('signature','hex65'),('subject','id'),('sessionId','id'),('expectedDomain','domain'),('expectedUri','uri'),('expectedChain','u64'),('issuerKeyId','id'),('issuerKeyEpoch','u64'),('sessionSeconds','u32')]
T=[('kid','id'),('keyEpoch','u64'),('challengeId','nonce'),('subject','id'),('chainId','u64'),('wallet','hex20'),('messageDigest','hex32'),('sessionId','id'),('bindingGeneration','u64'),('consentGeneration','u64'),('sessionSeconds','u32'),('expiresAt','u64'),('domain','domain'),('uri','uri'),('scope','scope'),('issuedAt','u64'),('contextExpiresAt','u64')]
def encode(fields,values,tag):
 if set(values)!=set(n for n,k in fields):raise ValueError('SCHEMA')
 out=bytearray(tag.encode('ascii')+b'\0')
 for name,kind in fields:
  v=values[name]
  if not isinstance(v,str):raise ValueError('TYPE')
  if kind in ('u64','u32'):
   if not re.fullmatch(r'(0|[1-9][0-9]*)',v):raise ValueError('INT')
   out+=int(v).to_bytes(8 if kind=='u64' else 4,'big');continue
  if kind.startswith('hex'):
   n=int(kind[3:]);p='0x' if n in (20,65) else ''
   if not re.fullmatch(re.escape(p)+r'[0-9a-f]{'+str(n*2)+r'}',v):raise ValueError('HEX')
   out+=bytes.fromhex(v[len(p):]);continue
  if kind=='id' and not re.fullmatch(r'[A-Za-z0-9_-]{1,128}',v):raise ValueError('ID')
  if kind=='nonce' and not re.fullmatch(r'[A-Za-z0-9]{8,128}',v):raise ValueError('NONCE')
  if kind=='audience' and v!='gflo-issuer-ib03u':raise ValueError('AUDIENCE')
  if kind=='scope' and v!='pie:xp:read':raise ValueError('SCOPE')
  if kind=='domain' and (not re.fullmatch(r'[a-z0-9.-]{1,255}(:[0-9]{1,5})?',v) or '..' in v):raise ValueError('DOMAIN')
  if kind=='uri' and (not re.fullmatch(r'https://[\x21-\x7e]{1,2040}',v) or '|' in v):raise ValueError('URI')
  if kind=='utf8' and ('\r' in v or any(0xd800<=ord(c)<=0xdfff for c in v)):raise ValueError('UNICODE')
  b=v.encode('utf8')
  if not b:raise ValueError('EMPTY')
  out+=len(b).to_bytes(4,'big')+b
 return bytes(out)
assert d['testOnly'] is True
for v in d['vectors']:
 a=encode(A,v['admission'],'GFLO:IB03U:ADMISSION:V1')
 t=encode(T,v['attestation'],'GFLO:IB03U:ATTESTATION:V1')
 assert len(a)==v['admissionLength'] and len(t)==v['attestationLength']
 assert hashlib.sha256(a).hexdigest()==v['admissionSha256']
 assert hashlib.sha256(t).hexdigest()==v['attestationSha256']
 assert hmac.new(bytes.fromhex(d['testOnlyMacKeyHex']),t,hashlib.sha256).hexdigest()==v['hmacSha256']
 with tempfile.TemporaryDirectory() as td:
  p=Path(td);(p/'pub.pem').write_text(d['publicSpkiPem']);(p/'msg').write_bytes(a)
  (p/'sig').write_bytes(bytes.fromhex(v['ed25519SignatureHex']))
  cmd=['openssl','pkeyutl','-verify','-pubin','-inkey',str(p/'pub.pem'),'-rawin','-in',str(p/'msg'),'-sigfile',str(p/'sig')]
  assert subprocess.run(cmd,capture_output=True).returncode==0
  (p/'msg').write_bytes(a[:-1]+bytes([a[-1]^1]))
  assert subprocess.run(cmd,capture_output=True).returncode!=0
 print('PASS Python/OpenSSL independent vectors:',v['label'])
print('IB03U_PYTHON_OPENSSL_INDEPENDENT_PASS')
