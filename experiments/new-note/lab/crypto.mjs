// ML-KEM-1024 receipt and SLH-DSA-SHAKE-128f owner roles. Private inputs use stdin.
import * as c from 'node:crypto';
import { readFileSync } from 'node:fs';

if (process.version !== 'v24.22.1' || process.versions.openssl !== '3.5.9') throw Error('unapproved Node/OpenSSL');
const input = readFileSync(0);
const cat = Buffer.concat;
const kemPrivate = Buffer.from('3054020100300b060960864801650304040304428040','hex');
const kemPublic = Buffer.from('30820632300b06096086480165030404030382062100','hex');
const slhPublic = Buffer.from('3030300b060960864801650304031b032100','hex');
function need(ok) { if (!ok) throw Error('invalid cryptographic role input'); }
function xof(label, pieces, width) {
  return c.createHash('shake256',{outputLength:width}).update(label+'\0').update(cat(pieces)).digest();
}
function privateKem(net, seed) {
  const key = cat([kemPrivate,xof('N7R1/KEM/seed',[net,seed],64)]);
  return c.createPrivateKey({key,type:'pkcs8',format:'der'});
}
function rawKem(privateKey) {
  const key = c.createPublicKey(privateKey).export({type:'spki',format:'der'});
  need(key.length === kemPublic.length+1568 && key.subarray(0,kemPublic.length).equals(kemPublic));
  return key.subarray(kemPublic.length);
}
function publicKey(prefix,raw) {
  return c.createPublicKey({key:cat([prefix,raw]),type:'spki',format:'der'});
}
function dem(secret,ct,pk,ad) { return xof('N7R1/DEM/key-iv',[secret,ct,pk,ad],44); }
function main(op) {
  // ad = networkID (48), output slot (1), canonical commitment (56).
  const ad = input.subarray(0,105);
  if (op === 'address') {
    need(input.length === 96); return rawKem(privateKem(input.subarray(0,48),input.subarray(48)));
  }
  if (op === 'seal') {
    need(input.length === 105+1568+160);
    const pk = input.subarray(105,105+1568);
    const {ciphertext, sharedKey} = c.encapsulate(publicKey(kemPublic,pk));
    const kv=dem(sharedKey,ciphertext,pk,ad);
    const ae=c.createCipheriv('aes-256-gcm',kv.subarray(0,32),kv.subarray(32));
    ae.setAAD(ad);
    return cat([ciphertext,ae.update(input.subarray(105+1568)),ae.final(),ae.getAuthTag()]);
  }
  if (op === 'open') {
    need(input.length === 105+48+48+1744);
    const key=privateKem(input.subarray(105,153),input.subarray(153,201));
    const ct=input.subarray(201,201+1568), kv=dem(c.decapsulate(key,ct),ct,rawKem(key),ad);
    const ae=c.createDecipheriv('aes-256-gcm',kv.subarray(0,32),kv.subarray(32));
    ae.setAAD(ad); ae.setAuthTag(input.subarray(-16));
    try { return cat([ae.update(input.subarray(201+1568,-16)),ae.final()]); }
    catch { return Buffer.alloc(0); } // An authenticated trial decryption miss.
  }
  if (op === 'auth-key') {
    need(!input.length);
    const k=c.generateKeyPairSync('slh-dsa-shake-128f');
    return cat([k.publicKey.export({type:'spki',format:'der'}).subarray(slhPublic.length),
                k.privateKey.export({type:'pkcs8',format:'der'})]);
  }
  if (op === 'sign') {
    need(input.length === 84+48);
    const key=c.createPrivateKey({key:input.subarray(0,84),type:'pkcs8',format:'der'});
    need(key.asymmetricKeyType === 'slh-dsa-shake-128f');
    return c.sign(null,input.subarray(84),key);
  }
  if (op === 'verify') {
    need(input.length === 32+48+17088);
    return Buffer.from([Number(c.verify(null,input.subarray(32,80),publicKey(slhPublic,input.subarray(0,32)),input.subarray(80)))]);
  }
  throw Error('unknown role');
}
process.stdout.write(main(process.argv[2]));
