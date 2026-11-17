// Canonical CP03 bytes. Public assertions intentionally never interpolate secret values.
import * as c from 'node:crypto';
import {LocalReceiptMiss} from './errors.mjs';
export const P=18446744069414584321n, MAX=1840960000000000n;
export const E_BYTES=2164,D_BYTES=1672;
export const headerBytes=()=>Buffer.from('4350523303010000','hex');
export function requireTrue(ok){if(!ok)throw new LocalReceiptMiss();}
export function fixed(b,n){requireTrue(Buffer.isBuffer(b)&&b.length===n);return b;}
export function u16(n){requireTrue(Number.isInteger(n)&&n>=0&&n<=65535);const b=Buffer.alloc(2);b.writeUInt16LE(n);return b;}
export function blob(b){requireTrue(Buffer.isBuffer(b)&&b.length<=0xffffffff);const n=Buffer.alloc(4);n.writeUInt32LE(b.length);return Buffer.concat([n,b]);}
export function tag(label){requireTrue(/^[A-Z-]+$/.test(label));const b=Buffer.from('PQPC/CP3/'+label,'ascii');return Buffer.concat([u16(b.length),b]);}
export function H48(label,...parts){return c.createHash('shake256',{outputLength:48}).update(Buffer.concat([tag(label),...parts])).digest();}
export function fields(b,n){fixed(b,n*8);for(let i=0;i<n;i++)requireTrue(b.readBigUInt64LE(i*8)<P);return b;}
export function noteBytes(b){fields(b,20);requireTrue(b.readBigUInt64LE(0)===0n&&b.readBigUInt64LE(8)<=MAX);return b;}
export function randomFields(n){
  requireTrue(n===5);const b=Buffer.alloc(n*8);
  for(let i=0;i<n;i++){let x;do{const candidate=c.randomBytes(8);x=candidate.readBigUInt64LE();candidate.fill(0);}while(x>=P);b.writeBigUInt64LE(x,i*8);}
  return b;
}
export function encodeNote(note,cm,memo=Buffer.alloc(0)){
  noteBytes(note);fields(cm,8);requireTrue(Buffer.isBuffer(memo)&&memo.length<=128);
  const b=Buffer.alloc(512);Buffer.from('CPNOTE03').copy(b);note.copy(b,8);cm.copy(b,168);b.writeUInt16LE(memo.length,232);memo.copy(b,234);return b;
}
export function decodeNote(b){
  fixed(b,512);requireTrue(b.subarray(0,8).equals(Buffer.from('CPNOTE03')));
  noteBytes(b.subarray(8,168));fields(b.subarray(168,232),8);const n=b.readUInt16LE(232);
  requireTrue(n<=128&&b.subarray(234+n,362).every(x=>x===0)&&b.subarray(362).every(x=>x===0));
  return {note:Buffer.from(b.subarray(8,168)),cm:Buffer.from(b.subarray(168,232)),memo:Buffer.from(b.subarray(234,234+n))};
}
export function wipeOpening(opening){if(opening)for(const k of ['note','cm','memo'])opening[k]?.fill(0);}
