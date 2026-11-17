// Research wallet key inventory. No expiry and no private bytes/digests are logged.
// Backup serialization returns PRIVATE bytes; storage/pipe ownership is the caller's duty.
import * as crypto from 'node:crypto';
import {createReceiptAdapter, newReceivingKey, randomFields} from '../../experiments/compact-receiving-v1/cp03/receipt.mjs';
import {WalletInputError} from './codec.mjs';

const FORMAT = 'CP03-PRIVATE-BACKUP-01';
const INVENTORY_FORMAT = 'CP03-KEY-INVENTORY-01';
const MAX_KEYS = 1024;
const MAX_BACKUP = 16 * 1024 * 1024;
const wallets = new WeakMap();
const leases = new WeakMap();
export class WalletOperationalError extends Error {
  constructor() { super('CP03 wallet operation failed'); this.name = 'WalletOperationalError'; }
}
function need(value) { if (!value) throw new WalletInputError(); }
function fixed(value, size) { need(Buffer.isBuffer(value) && value.length === size); return value; }
function state(token) { const value = wallets.get(token); need(!!value); return value; }
function decimal(value) { need(typeof value === 'string' && /^(0|[1-9][0-9]*)$/.test(value)); return BigInt(value); }
function bytes(value, size) {
  need(typeof value === 'string' && value.length === size * 2 && /^[a-f0-9]*$/.test(value));
  return Buffer.from(value, 'hex');
}
function objectKeys(value, keys) {
  need(value && typeof value === 'object' && !Array.isArray(value));
  need(Object.keys(value).sort().join(',') === [...keys].sort().join(','));
}
function brand(value) {
  const token = Object.freeze({type: 'CP03-private-wallet'}); wallets.set(token, value); return token;
}
function exportedKey(key) {
  const der = key.export({format: 'der', type: 'pkcs8'});
  try { return der.toString('base64'); }
  finally { der.fill(0); }
}
function inventoryOf(value) {
  const label = Buffer.from('PQPC/CP3/WALLET-INVENTORY');
  const tag = Buffer.alloc(2); tag.writeUInt16LE(label.length);
  const version = Buffer.alloc(8); version.writeBigUInt64LE(value.version);
  const count = Buffer.alloc(2); count.writeUInt16LE(value.keys.length);
  const publicBytes = Buffer.concat([value.chain, value.id, version, count, ...value.keys.map(k => k.descriptor)]);
  const size = Buffer.alloc(4); size.writeUInt32LE(publicBytes.length);
  // Only PUBLIC descriptors/inventory metadata, never private keys or backup bytes.
  const id = crypto.createHash('sha3-512').update(tag).update(label).update(size).update(publicBytes).digest('hex');
  return {format: INVENTORY_FORMAT, chain: value.chain.toString('hex'), wallet_id: value.id.toString('hex'),
    version: value.version.toString(), key_count: value.keys.length.toString(), inventory_id: id};
}
export function publicInventory(wallet) {
  try { return inventoryOf(state(wallet)); }
  catch (error) { if (error instanceof WalletInputError) throw error; throw new WalletOperationalError(); }
}
export function createWallet(chain, helperSha256) {
  fixed(chain, 32); let spending;
  try {
    const adapter = createReceiptAdapter(chain, helperSha256);
    spending = randomFields(5);
    const owner = adapter.auth(spending), pair = newReceivingKey();
    const value = {chain: Buffer.from(chain), id: crypto.randomBytes(32), version: 1n, helperSha256,
      spending, adapter, keys: [{descriptor: adapter.descriptor(owner, pair.publicKey), key: pair.privateKey}]};
    return brand(value);
  } catch { spending?.fill(0); throw new WalletOperationalError(); }
}
export function rotateReceivingKey(wallet) {
  const value = state(wallet); need(!value.activeLease && value.keys.length < MAX_KEYS && value.version < (1n << 64n) - 1n);
  try {
    const pair = newReceivingKey();
    const descriptor = value.adapter.descriptor(value.adapter.auth(value.spending), pair.publicKey);
    if (value.keys.some(k => k.descriptor.equals(descriptor))) throw new WalletOperationalError();
    const returned = Buffer.from(descriptor);
    const nextKeys = [...value.keys, {descriptor, key: pair.privateKey}];
    const nextVersion = value.version + 1n;
    // Existing keys remain retained. A failed creation never deletes prior keys.
    value.keys = nextKeys; value.version = nextVersion;
    return returned;
  } catch { throw new WalletOperationalError(); }
}
export function descriptor(wallet, index) {
  const value = state(wallet); need(Number.isInteger(index) && index >= 0 && index < value.keys.length);
  return Buffer.from(value.keys[index].descriptor);
}
export function exportBackup(wallet) {
  const value = state(wallet);
  try {
    const content = {format: FORMAT, chain: value.chain.toString('hex'), wallet_id: value.id.toString('hex'),
      version: value.version.toString(), spending_key_le: value.spending.toString('hex'),
      keys: value.keys.map(k => ({descriptor: k.descriptor.toString('hex'),
        private_key_pkcs8: exportedKey(k.key)}))};
    const backup = Buffer.from(JSON.stringify(content) + '\n');
    if (backup.length > MAX_BACKUP) { backup.fill(0); throw new WalletInputError(); }
    return backup;
  } catch { throw new WalletOperationalError(); }
}
export function restoreBackup(backup, configuredChain, helperSha256, expectedInventory = null) {
  fixed(configuredChain, 32);
  need(Buffer.isBuffer(backup) && backup.length > 0 && backup.length <= MAX_BACKUP);
  let spending, value;
  try {
    const content = JSON.parse(backup.toString('utf8'));
    objectKeys(content, ['format', 'chain', 'wallet_id', 'version', 'spending_key_le', 'keys']);
    need(content.format === FORMAT && bytes(content.chain, 32).equals(configuredChain));
    const chain = bytes(content.chain, 32), id = bytes(content.wallet_id, 32), version = decimal(content.version);
    need(version > 0n && version < (1n << 64n) && Array.isArray(content.keys) &&
      content.keys.length > 0 && content.keys.length <= MAX_KEYS);
    for (const entry of content.keys) objectKeys(entry, ['descriptor', 'private_key_pkcs8']);
    // Reconstruct the fixed export order, not the incoming property order.
    // This also rejects duplicate properties, invalid UTF-8 and alternate escapes.
    const canonical = Buffer.from(JSON.stringify({format: content.format, chain: content.chain,
      wallet_id: content.wallet_id, version: content.version, spending_key_le: content.spending_key_le,
      keys: content.keys.map(k => ({descriptor: k.descriptor, private_key_pkcs8: k.private_key_pkcs8}))}) + '\n');
    try { need(canonical.equals(backup)); }
    finally { canonical.fill(0); }
    spending = bytes(content.spending_key_le, 40);
    const adapter = createReceiptAdapter(chain, helperSha256);
    const owner = adapter.auth(spending), seen = new Set(), keys = [];
    for (const entry of content.keys) {
      objectKeys(entry, ['descriptor', 'private_key_pkcs8']);
      const d = bytes(entry.descriptor, 1672), desc = adapter.parseDescriptor(d);
      need(desc.owner.equals(owner) && !seen.has(entry.descriptor)); seen.add(entry.descriptor);
      need(typeof entry.private_key_pkcs8 === 'string' && entry.private_key_pkcs8.length <= 16384 &&
        /^[A-Za-z0-9+/]*={0,2}$/.test(entry.private_key_pkcs8));
      const der = Buffer.from(entry.private_key_pkcs8, 'base64');
      let key, exported;
      try {
        need(der.toString('base64') === entry.private_key_pkcs8);
        key = crypto.createPrivateKey({key: der, format: 'der', type: 'pkcs8'});
        exported = key.export({format: 'der', type: 'pkcs8'});
        need(exported.equals(der));
      } finally { der.fill(0); exported?.fill(0); }
      // Genuine descriptor/private-key/AUTH correspondence, not self-declared backup metadata.
      const recipient = adapter.prepareRecipient(d, key, spending); adapter.disposeRecipient(recipient);
      // Finite native consistency self-check for the imported secret/public pair.
      // It does not establish an expanded-key validation or KEM security theorem.
      let shared, recovered;
      try {
        const encapsulated = crypto.encapsulate(desc.pk); shared = encapsulated.sharedKey;
        recovered = crypto.decapsulate(key, encapsulated.ciphertext);
        need(Buffer.isBuffer(shared) && Buffer.isBuffer(recovered) && shared.length === 32 &&
          recovered.length === 32 && crypto.timingSafeEqual(shared, recovered));
      } finally { shared?.fill(0); recovered?.fill(0); }
      keys.push({descriptor: d, key});
    }
    value = {chain, id, version, spending, adapter, keys, helperSha256};
    const actualInventory = inventoryOf(value);
    if (expectedInventory !== null) {
      objectKeys(expectedInventory, Object.keys(actualInventory));
      need(Object.keys(actualInventory).every(k => expectedInventory[k] === actualInventory[k]));
    }
    return {wallet: brand(value), inventory: actualInventory,
      expected_inventory_matched: expectedInventory !== null,
      // The API cannot establish the provenance/freshness of its caller's value.
      inventory_completeness_basis: expectedInventory === null ? 'unknown' : 'conditional-on-independent-current-inventory'};
  } catch {
    spending?.fill(0);
    // Native/JSON failures never print secret input or turn into a complete empty wallet.
    throw new WalletOperationalError();
  }
}
// Internal wallet operations use these handles in RAM only; never serialize them.
export function withWallet(wallet, operation) {
  const value = state(wallet); need(typeof operation === 'function'); return operation(value);
}
// Internal coordinator capability. The holder alone can release this lease;
// callers keep no key copy in the lease or its public inventory identity.
export function leaseWallet(wallet, helperSha256) {
  const value = state(wallet); need(!value.activeLease && value.helperSha256 === helperSha256);
  const inventory = Object.freeze(inventoryOf(value));
  const token = Object.freeze({type: 'CP03-private-wallet-inventory-lease'});
  leases.set(token, {wallet, value, inventory}); value.activeLease = token;
  return token;
}
export function withWalletLease(token, operation) {
  const held = leases.get(token); need(!!held && typeof operation === 'function');
  need(wallets.get(held.wallet) === held.value && held.value.activeLease === token);
  const actual = inventoryOf(held.value);
  need(Object.keys(held.inventory).every(key => actual[key] === held.inventory[key]));
  return operation(held.value, held.inventory);
}
export function releaseWalletLease(token) {
  const held = leases.get(token); need(!!held && held.value.activeLease === token);
  held.value.activeLease = null; leases.delete(token);
}
export function disposeWallet(wallet) {
  const value = state(wallet); need(!value.activeLease);
  value.spending.fill(0); value.keys.length = 0; wallets.delete(wallet);
  // Native KeyObjects and immutable JS strings may survive until GC; no erasure theorem.
}
