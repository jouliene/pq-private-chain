// Secret data travels only through private stdin/stdout pipes to its owning wallet.
import * as c from 'node:crypto';
import { readFileSync } from 'node:fs';
import assert from 'node:assert/strict';

assert.equal(process.version, 'v24.22.1');
assert.equal(process.versions.openssl, '3.5.9');
const op = process.argv[2], input = readFileSync(0), chain = input.subarray(0,64);
const hash = (tag,...pieces) => c.createHash('shake256',{outputLength:64})
  .update(Buffer.concat([Buffer.of(0xf1,tag), ...pieces])).digest();
const privatePrefix = Buffer.from('3054020100300b060960864801650304040304428040', 'hex');
const publicPrefix = Buffer.from('30820632300b06096086480165030404030382062100', 'hex');

function restore(seed) {
  const dk = c.createPrivateKey({type:'pkcs8',format:'der',
    key:Buffer.concat([privatePrefix,hash(2,chain,seed)])});
  const der = c.createPublicKey(dk).export({type:'spki',format:'der'});
  assert.ok(der.subarray(0,publicPrefix.length).equals(publicPrefix));
  assert.equal(der.length,publicPrefix.length+1568);
  const owner = hash(3,hash(1,chain,seed));
  return {dk,descriptor:Buffer.concat([owner,der.subarray(publicPrefix.length)])};
}

function material(descriptor, ss, context, ciphertext) {
  const ad = hash(18,chain,context,ciphertext);
  const salt = hash(19,chain,descriptor);
  const bytes = Buffer.from(c.hkdfSync('sha384',ss,salt,ad,44));
  return {ad,key:bytes.subarray(0,32),iv:bytes.subarray(32)};
}

function run() {
  if (op === 'descriptor') {
    assert.equal(input.length,128);
    return restore(input.subarray(64)).descriptor;
  }
  // context = occurrence64 || slot1 || CM64.
  const context = input.subarray(64,193), cm = context.subarray(65);
  assert.ok(context.length === 129 && context[64] <= 1);
  if (op === 'seal') {
    assert.equal(input.length,193+1632+208);
    const descriptor = input.subarray(193,1825), plain=input.subarray(1825);
    assert.ok(descriptor.subarray(0,64).equals(plain.subarray(0,64)));
    assert.ok(hash(4,chain,plain).equals(cm));
    const ek = c.createPublicKey({type:'spki',format:'der',
      key:Buffer.concat([publicPrefix,descriptor.subarray(64)])});
    const {ciphertext,sharedKey} = c.encapsulate(ek);
    const {ad,key,iv} = material(descriptor,sharedKey,context,ciphertext);
    const ae=c.createCipheriv('aes-256-gcm',key,iv);
    ae.setAAD(ad);
    return Buffer.concat([ciphertext,ae.update(plain),ae.final(),ae.getAuthTag()]);
  }
  assert.equal(op,'open');
  assert.equal(input.length,193+64+1792);
  const {dk,descriptor} = restore(input.subarray(193,257));
  const env=input.subarray(257), ct=env.subarray(0,1568);
  const {ad,key,iv} = material(descriptor,c.decapsulate(dk,ct),context,ct);
  const ae=c.createDecipheriv('aes-256-gcm',key,iv);
  ae.setAAD(ad);
  ae.setAuthTag(env.subarray(-16));
  const tentative=ae.update(env.subarray(1568,-16));
  let final;
  try {
    final=ae.final();
  } catch (err) {
    if (err instanceof Error && err.message === 'Unsupported state or unable to authenticate data') return Buffer.alloc(0);
    throw err;
  }
  const plain=Buffer.concat([tentative,final]);
  if (!plain.subarray(0,64).equals(descriptor.subarray(0,64)) ||
      !hash(4,chain,plain).equals(cm)) return Buffer.alloc(0);
  return plain;
}
process.stdout.write(run());
