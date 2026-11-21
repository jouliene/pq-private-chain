// Private inputs and outputs are local pipes. Only raw public keys and signatures go on wire.
import * as c from 'node:crypto';
import {readFileSync} from 'node:fs';
import assert from 'node:assert/strict';
assert.equal(process.version,'v24.22.1');
assert.equal(process.versions.openssl,'3.5.9');
const op=process.argv[2], input=readFileSync(0);
const prefix=Buffer.from('3050300b060960864801650304031e034100','hex');

function run() {
  if (op === 'key') {
    assert.equal(input.length,0);
    const {publicKey,privateKey}=c.generateKeyPairSync('slh-dsa-shake-256s');
    const pk=publicKey.export({format:'der',type:'spki'});
    assert.equal(pk.length,prefix.length+64);
    assert.ok(pk.subarray(0,prefix.length).equals(prefix));
    return Buffer.concat([pk.subarray(prefix.length),privateKey.export({format:'der',type:'pkcs8'})]);
  }
  if (op === 'sign') {
    const dk=c.createPrivateKey({key:input.subarray(64),format:'der',type:'pkcs8'});
    assert.equal(dk.asymmetricKeyType,'slh-dsa-shake-256s');
    const sig=c.sign(null,input.subarray(0,64),dk);
    assert.equal(sig.length,29792);
    return sig;
  }
  assert.equal(op,'verify');
  assert.equal(input.length,128+29792);
  const pk=c.createPublicKey({key:Buffer.concat([prefix,input.subarray(64,128)]),format:'der',type:'spki'});
  return Buffer.of(c.verify(null,input.subarray(0,64),pk,input.subarray(128))?1:0);
}
process.stdout.write(run());
