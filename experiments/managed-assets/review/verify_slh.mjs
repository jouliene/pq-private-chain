// Independent FIPS 205 verification using OpenSSL, without issuer or wallet inputs.
import { createPublicKey, verify } from 'node:crypto';
import { readFileSync } from 'node:fs';

if (process.version !== 'v24.22.1' || process.versions.openssl !== '3.5.9') {
  throw Error('expected the Node 24.22.1 / OpenSSL 3.5.9 review provider');
}
const request = readFileSync(0);
const width = 32 + 32 + 17088;
if (!request.length || request.length % width !== 0) throw Error('incomplete signature case');
const spkiPrefix = Buffer.from('3030300b060960864801650304031b032100', 'hex');
for (let i = 0; i < request.length; i += width) {
  const key = createPublicKey({ key: Buffer.concat([spkiPrefix, request.subarray(i, i+32)]), format: 'der', type: 'spki' });
  if (key.asymmetricKeyType !== 'slh-dsa-shake-128f') throw Error('unexpected verifier suite');
  const accepted = verify(null, request.subarray(i+32, i+64), key, request.subarray(i+64, i+width));
  process.stdout.write(accepted ? '1' : '0');
}
