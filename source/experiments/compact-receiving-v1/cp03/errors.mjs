// Payload-free error classes; operational failures must never become a recipient miss.
export class LocalReceiptMiss extends Error {constructor(){super('CP03_LOCAL_MISS');this.name='LocalReceiptMiss';}}
export class HashCoreFailure extends Error {constructor(){super('CP03_HASH_HELPER_FAILURE');this.name='HashCoreFailure';}}
export class ReceiptOperationalFailure extends Error {constructor(){super('CP03_RECEIPT_OPERATIONAL_FAILURE');this.name='ReceiptOperationalFailure';}}
export function classified(error){
  return error instanceof LocalReceiptMiss||error instanceof HashCoreFailure||error instanceof ReceiptOperationalFailure
    ? error : new ReceiptOperationalFailure();
}
