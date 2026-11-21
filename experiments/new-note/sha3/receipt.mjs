// Isolated receipt component. Only aggregate timings and statuses leave the process.
import assert from 'node:assert/strict';
import * as c from 'node:crypto';

const suite = Buffer.from('N3R1');
const network = Buffer.alloc(48, 17);
const h = (tag, ...fields) => c.createHash('sha3-384')
    .update(Buffer.concat([suite, Buffer.of(tag), ...fields])).digest();
const derive = (tag, backup, outputLength) => c.createHash('shake256', {outputLength})
    .update(Buffer.concat([suite, Buffer.of(tag), network, backup])).digest();
const spki = Buffer.from('30820632300b06096086480165030404030382062100', 'hex');
const pkcs8 = Buffer.from('3054020100300b060960864801650304040304428040', 'hex');

function restore(backup) {
    const seed = derive(11, backup, 64);
    const privateKey = c.createPrivateKey({key: Buffer.concat([pkcs8, seed]), type:'pkcs8',format:'der'});
    const publicKey = c.createPublicKey(privateKey);
    const encoded = publicKey.export({type:'spki',format:'der'});
    assert.equal(encoded.length, spki.length + 1568);
    assert.ok(encoded.subarray(0, spki.length).equals(spki));
    const raw = encoded.subarray(spki.length);
    const owner = h(1, network, derive(10, backup, 48));
    return {privateKey, publicKey, owner, descriptor: h(12, network, owner, raw)};
}

function material(secret, descriptor, context, kemCT) {
    const aad = h(13, context, kemCT);
    const out = Buffer.from(c.hkdfSync('sha384', secret, descriptor, aad, 44));
    return {key:out.subarray(0,32), nonce:out.subarray(32), aad};
}

function seal(recipient, plaintext, context) {
    const enc = c.encapsulate(recipient.publicKey);
    const {key, nonce, aad} = material(enc.sharedKey, recipient.descriptor, context, enc.ciphertext);
    const cipher = c.createCipheriv('aes-256-gcm', key, nonce);
    cipher.setAAD(aad);
    return Buffer.concat([enc.ciphertext, cipher.update(plaintext), cipher.final(), cipher.getAuthTag()]);
}

function open(recipient, envelope, context, commitment) {
    assert.equal(envelope.length, 1728);
    const kemCT = envelope.subarray(0, 1568);
    const secret = c.decapsulate(recipient.privateKey, kemCT);
    const {key, nonce, aad} = material(secret, recipient.descriptor, context, kemCT);
    const decipher = c.createDecipheriv('aes-256-gcm',key,nonce);
    decipher.setAAD(aad);
    decipher.setAuthTag(envelope.subarray(-16));
    const tentative = decipher.update(envelope.subarray(1568,-16));
    // Check tag through local reencryption. Native provider errors remain fatal.
    const verifyTag = c.createCipheriv('aes-256-gcm',key,nonce);
    verifyTag.setAAD(aad);
    const roundtrip = Buffer.concat([verifyTag.update(tentative),verifyTag.final()]);
    assert.ok(roundtrip.equals(envelope.subarray(1568,-16)));
    if (!c.timingSafeEqual(verifyTag.getAuthTag(),envelope.subarray(-16))) return null;
    const plain = Buffer.concat([tentative, decipher.final()]);
    if (!plain.subarray(0,48).equals(recipient.owner) || !h(2,network,plain).equals(commitment)) return null;
    return plain;
}

const backup = c.randomBytes(48), offered = restore(backup), restored = restore(backup);
const outsider = restore(c.randomBytes(48));
const totals = Buffer.alloc(16);
totals.writeBigUInt64LE(4n); totals.writeBigUInt64LE(13n, 8);
const plain = Buffer.concat([offered.owner, c.randomBytes(32), c.randomBytes(48), totals]);
const commitment = h(2, network, plain);
const context = h(14, network, Buffer.of(0), c.randomBytes(48), c.randomBytes(48), Buffer.of(0), commitment);
const ct = seal(offered, plain, context);
assert.ok(open(restored, ct, context, commitment).equals(plain));
assert.equal(open(outsider, ct, context, commitment), null);
assert.equal(open(restored, ct, Buffer.alloc(48), commitment), null);
assert.equal(open(restored, ct, context, Buffer.alloc(48)), null);
const altered = Buffer.from(ct); altered[1570] ^= 1;
assert.equal(open(restored, altered, context, commitment), null);
const times = [];
for (const [label,operation] of [
    ['seal', () => seal(offered,plain,context)],
    ['restore_hit', () => open(restored,ct,context,commitment)],
    ['unrelated_key_miss', () => open(outsider,ct,context,commitment)]]) {
    for (let i=0; i<32; i++) operation();
    const start = process.cpuUsage();
    for (let i=0; i<512; i++) operation();
    const elapsed=process.cpuUsage(start);
    times.push([label,(elapsed.user+elapsed.system)/512]);
}
console.log(JSON.stringify({node:process.version,openssl:process.versions.openssl,receipt_bytes:ct.length,
    checked:'seed restore, hit, unrelated key, altered context, commitment and ciphertext',
    cpu_us_per_operation:Object.fromEntries(times), maxRSS_KiB:process.resourceUsage().maxRSS}));
