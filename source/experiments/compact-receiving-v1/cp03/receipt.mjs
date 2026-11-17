// Research Node/native receipt adapter. CP field hashes exist only in the pinned Rust helper.
import * as c from 'node:crypto';
import {fixedHashCore} from './hash-core.mjs';
import {LocalReceiptMiss,ReceiptOperationalFailure,classified} from './errors.mjs';
import {P,MAX,E_BYTES,D_BYTES,headerBytes,requireTrue,fixed,u16,blob,tag,H48,fields,noteBytes,randomFields,encodeNote,decodeNote,wipeOpening} from './codec.mjs';
export {P,MAX,E_BYTES,D_BYTES,randomFields,encodeNote,wipeOpening};
const HEADER=headerBytes();
const SPKI=Buffer.from('30820632300b06096086480165030404030382062100','hex');
export function rawPublic(pk){
  requireTrue(pk?.asymmetricKeyType==='ml-kem-1024'&&pk.type==='public');
  const der=pk.export({type:'spki',format:'der'});
  requireTrue(der.length===SPKI.length+1568&&der.subarray(0,SPKI.length).equals(SPKI));
  return Buffer.from(der.subarray(SPKI.length));
}
export function newReceivingKey(){return c.generateKeyPairSync('ml-kem-1024');}
export function makeNote(amount,owner){
  requireTrue(typeof amount==='bigint'&&amount>=0n&&amount<=MAX);fields(owner,8);
  const n=Buffer.alloc(160);n.writeBigUInt64LE(amount,8);owner.copy(n,16);
  const rho=randomFields(5),r=randomFields(5);try{rho.copy(n,80);r.copy(n,120);}finally{rho.fill(0);r.fill(0);}return n;
}
export function createReceiptAdapter(configuredChain,trustedHelperSha256){
  const chain=Buffer.from(fixed(configuredChain,32)),core=fixedHashCore(trustedHelperSha256);
  const contexts=new WeakMap(),recipients=new WeakMap();
  function parseDescriptor(d){
    fixed(d,D_BYTES);requireTrue(d.subarray(0,4).equals(Buffer.from('CPD3'))&&d.readUInt16LE(4)===3&&d.readUInt16LE(6)===1&&d.subarray(8,40).equals(chain));
    const owner=Buffer.from(fields(d.subarray(40,104),8)),raw=d.subarray(104);
    for(let i=0;i<1536;i+=3){requireTrue(raw[i]+((raw[i+1]&15)<<8)<3329);requireTrue((raw[i+1]>>4)+(raw[i+2]<<4)<3329);}
    const pk=c.createPublicKey({key:Buffer.concat([SPKI,raw]),type:'spki',format:'der'});requireTrue(rawPublic(pk).equals(raw));
    return {pk,owner,D:H48('DESCRIPTOR',blob(d))};
  }
  function descriptor(owner,pk){fields(owner,8);const d=Buffer.concat([Buffer.from('CPD3'),u16(3),u16(1),chain,owner,rawPublic(pk)]);parseDescriptor(d);return d;}
  function state(token){const x=contexts.get(token);requireTrue(!!x);return x;}
  function brandContext(result,ordinal){
    fields(result,40);const cm=Buffer.from(result.subarray(192+64*ordinal,256+64*ordinal));
    const x={core:Buffer.from(result.subarray(0,64)),origin:Buffer.from(result.subarray(64+64*ordinal,128+64*ordinal)),cm,ordinal};
    x.C=Buffer.concat([chain,u16(3),u16(1),x.core,u16(ordinal),cm,HEADER]);fixed(x.C,174);
    const token=Object.freeze({type:'CP03-statement-derived-context'});contexts.set(token,x);return token;
  }
  function context(statement,ordinal){requireTrue(ordinal===0||ordinal===1);return brandContext(core.statement(chain,statement),ordinal);}
  function contextsBatch(statements){
    // The whole child result and every response record have passed before any token is minted.
    const records=core.statements(chain,statements);
    return records.map(record=>[brandContext(record,0),brandContext(record,1)]);
  }
  function contextInfo(token){const x=state(token);return {chain:Buffer.from(chain),core:Buffer.from(x.core),origin:Buffer.from(x.origin),cm:Buffer.from(x.cm),ordinal:x.ordinal};}
  function material(ss,D,C,ct,nonce){
    if(!Buffer.isBuffer(ss)||ss.length!==32)throw new ReceiptOperationalFailure();const salt=H48('RECEIPT-SALT',C,ct,nonce);
    // Native HKDF performs the exact Extract/Expand pair for each labelled output.
    let enc,com;try {
      enc=Buffer.from(c.hkdfSync('sha384',ss,salt,Buffer.concat([tag('RECEIPT-ENC'),D,C]),32));
      com=Buffer.from(c.hkdfSync('sha384',ss,salt,Buffer.concat([tag('RECEIPT-COM'),D,C]),48));
      return {enc,com,aad:Buffer.concat([tag('RECEIPT-AAD'),C,D,ct,nonce])};
    }catch{enc?.fill(0);com?.fill(0);throw new ReceiptOperationalFailure();}
  }
  function encryptPayload(d,token,plain){
    fixed(plain,512);const desc=parseDescriptor(d),x=state(token);
    const {sharedKey:ss,ciphertext:ct}=c.encapsulate(desc.pk);let m;
    try {if(!Buffer.isBuffer(ss)||ss.length!==32||!Buffer.isBuffer(ct)||ct.length!==1568)throw new ReceiptOperationalFailure();const nonce=c.randomBytes(12);m=material(ss,desc.D,x.C,ct,nonce);
      const cipher=c.createCipheriv('aes-256-gcm',m.enc,nonce,{authTagLength:16});cipher.setAAD(m.aad,{plaintextLength:512});
      const encrypted=Buffer.concat([cipher.update(plain),cipher.final()]),auth=cipher.getAuthTag();
      const KC=H48('RECEIPT-KC',m.com,desc.D,x.C,ct,nonce,encrypted,auth);
      return fixed(Buffer.concat([HEADER,ct,nonce,encrypted,auth,KC]),E_BYTES);
    } finally {ss.fill(0);m?.enc.fill(0);m?.com.fill(0);}
  }
  function seal(d,token,note,memo){
    const desc=parseDescriptor(d),x=state(token);noteBytes(note);
    requireTrue(note.subarray(16,80).equals(desc.owner)&&core.note(chain,note).equals(x.cm));
    const plain=encodeNote(note,x.cm,memo);try{return encryptPayload(d,token,plain);}finally{plain.fill(0);}
  }
  function prepareRecipient(d,sk,spendingKey){
    const desc=parseDescriptor(d);fields(spendingKey,5);
    requireTrue(sk?.asymmetricKeyType==='ml-kem-1024'&&sk.type==='private');
    requireTrue(rawPublic(c.createPublicKey(sk)).equals(rawPublic(desc.pk))&&core.auth(chain,spendingKey).equals(desc.owner));
    const token=Object.freeze({type:'CP03-prepared-recipient'});
    recipients.set(token,{...desc,sk,key:Buffer.from(spendingKey)});return token;
  }
  function disposeRecipient(token){const p=recipients.get(token);if(p){p.key.fill(0);recipients.delete(token);}}
  function openStrict(e,recipient,token){
    fixed(e,E_BYTES);requireTrue(e.subarray(0,8).equals(HEADER));const p=recipients.get(recipient),x=state(token);requireTrue(!!p);
    const ct=e.subarray(8,1576),nonce=e.subarray(1576,1588),encrypted=e.subarray(1588,2100),auth=e.subarray(2100,2116),kc=e.subarray(2116);
    let ss,m,plain,opening;
    try {ss=c.decapsulate(p.sk,ct);m=material(ss,p.D,x.C,ct,nonce);
      requireTrue(c.timingSafeEqual(kc,H48('RECEIPT-KC',m.com,p.D,x.C,ct,nonce,encrypted,auth)));
      const decipher=c.createDecipheriv('aes-256-gcm',m.enc,nonce,{authTagLength:16});decipher.setAAD(m.aad,{plaintextLength:512});decipher.setAuthTag(auth);
      const first=decipher.update(encrypted);let last,checkChunk,checkTail,roundtrip,computedTag;
      try {
        // Native Final exceptions are not a typed authentication verdict. Recompute
        // via native AES-GCM locally; no tentative plaintext or bytes are emitted.
        const check=c.createCipheriv('aes-256-gcm',m.enc,nonce,{authTagLength:16});
        check.setAAD(m.aad,{plaintextLength:512});
        checkChunk=check.update(first);checkTail=check.final();
        roundtrip=Buffer.concat([checkChunk,checkTail]);computedTag=check.getAuthTag();
        if(first.length!==512||roundtrip.length!==encrypted.length||computedTag.length!==16||!c.timingSafeEqual(roundtrip,encrypted))throw new ReceiptOperationalFailure();
        requireTrue(c.timingSafeEqual(computedTag,auth));
        // Every native exception, including this final check, remains operational.
        last=decipher.final();plain=Buffer.concat([first,last]);
      }finally{first.fill(0);last?.fill(0);checkChunk?.fill(0);checkTail?.fill(0);roundtrip?.fill(0);computedTag?.fill(0);}
      opening=decodeNote(plain);
      requireTrue(opening.note.subarray(16,80).equals(p.owner)&&opening.cm.equals(x.cm)&&core.note(chain,opening.note).equals(x.cm));
      return opening;
    } catch(error) {wipeOpening(opening);throw classified(error);}
    finally {ss?.fill(0);m?.enc.fill(0);m?.com.fill(0);plain?.fill(0);}
  }
  function tryOpenPrepared(e,recipient,token){try{return openStrict(e,recipient,token);}catch(error){if(error instanceof LocalReceiptMiss)return null;throw classified(error);}}
  function tryOpen(e,d,sk,spendingKey,token){let p;try{p=prepareRecipient(d,sk,spendingKey);return tryOpenPrepared(e,p,token);}catch(error){if(error instanceof LocalReceiptMiss)return null;throw classified(error);}finally{if(p)disposeRecipient(p);}}
  function digest(token,e){const x=state(token);fixed(e,E_BYTES);requireTrue(e.subarray(0,8).equals(HEADER));return H48('RECEIPT',chain,x.core,u16(x.ordinal),blob(e));}
  function collectLocalCandidates(retainedRecipients,entries){
    requireTrue(Array.isArray(retainedRecipients)&&retainedRecipients.length>0&&retainedRecipients.length<=1024&&Array.isArray(entries)&&entries.length<=512);
    for(const r of retainedRecipients)requireTrue(recipients.has(r));
    const result=[],seen=new Set();let pending=null;
    try {for(const entry of entries){const x=state(entry.context),identity=x.origin.toString('hex')+':'+x.cm.toString('hex');requireTrue(!seen.has(identity));seen.add(identity);
      pending=null;
      // Try every retained key even after success; no expiry, clock or network callback.
      for(const r of retainedRecipients){const opening=tryOpenPrepared(entry.envelope,r,entry.context);if(!opening)continue;
        if(pending){const equal=pending.opening.note.equals(opening.note);wipeOpening(opening);requireTrue(equal);}else{const p=recipients.get(r);let nf;try{nf=core.nf(chain,p.key,x.origin,x.cm);}catch(error){wipeOpening(opening);throw classified(error);}pending={opening,nf,origin:Buffer.from(x.origin),cm:Buffer.from(x.cm),funding_authenticated:false,spentness_checked:false};}}
      if(pending)result.push(pending);pending=null;
    }return {candidates:result,history_complete:false,inventory_complete:false,funding_authenticated:false};
    }catch(error){wipeOpening(pending?.opening);for(const x of result)wipeOpening(x.opening);throw classified(error);}
  }
  const api={descriptor,parseDescriptor,context,contextsBatch,contextInfo,seal,prepareRecipient,disposeRecipient,tryOpenPrepared,tryOpen,digest,collectLocalCandidates,
    auth:(key)=>{fields(key,5);return core.auth(chain,key);},
    commitment:(note)=>{noteBytes(note);return core.note(chain,note);},
    // Research controls only: permits authenticated malformed openings, never an admission path.
    sealAuthenticatedPayloadForControl:encryptPayload};
  return Object.freeze(Object.fromEntries(Object.entries(api).map(([name,fn])=>[name,(...args)=>{try{return fn(...args);}catch(error){throw classified(error);}}])));
}
