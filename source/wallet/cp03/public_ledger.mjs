// Fixed local PUBLIC ledger CLI adapter. Operator configuration is not transaction data.
import * as crypto from 'node:crypto';
import * as fs from 'node:fs';
import * as path from 'node:path';
import {spawnSync} from 'node:child_process';

const P = 18446744069414584321n, MAX = 1840960000000000n;
const U64 = (1n << 64n) - 1n, LEAVES = 1n << 40n;
const WALL_MS = 120000, OUTPUT_BYTES = 32768, BINARY_BYTES = 64 * 1024 * 1024;
const OPS = new Set(['init', 'head', 'admit', 'replay', 'rollback', 'membership', 'spent', 'scan', 'check-scan']);
const MUTATIONS = new Set(['init', 'admit', 'replay', 'rollback']);
const PUBLICATIONS = new Set(['scan', 'check-scan']);
const REJECTIONS = new Set(['Codec', 'Identity', 'Chain', 'Fee', 'Accounting', 'Capacity',
  'Anchor', 'Replay', 'Source', 'Receipt', 'Block']);
const OPERATIONAL = new Set(['Storage', 'Io', 'State', 'Missing', 'Proof', 'HistoryHashProvider',
  'StorageSchemaUnsupported', 'ArchiveBacklog', 'RetentionPolicy', 'HistoryUnavailable',
  'ArchiveCorrupt', 'ArchiveIo', 'ArchiveBusy',
  'ProtocolManifestUnavailable', 'SourceSignatureProviderUnavailable',
  'TransactionOutcomeUnknown', 'RollbackFailed']);
const CLI_ERRORS = new Set([...REJECTIONS, ...OPERATIONAL]);
const ENV = Object.freeze({PATH: '/usr/bin:/bin', LANG: 'C', LC_ALL: 'C', TZ: 'UTC',
  RUST_BACKTRACE: '0', RUST_LOG: 'off', RAYON_NUM_THREADS: '1'});

export class PublicLedgerInputError extends Error {
  constructor() { super('CP03 public ledger input rejected'); this.name = 'PublicLedgerInputError'; }
}
export class PublicLedgerOperationalError extends Error {
  constructor(operation, code = 'Transport', attempted = false) {
    super('CP03 public ledger operation failed'); this.name = 'PublicLedgerOperationalError';
    this.operation = OPS.has(operation) ? operation : 'prepare';
    this.code = OPERATIONAL.has(code) || ['Transport', 'Binary', 'Output', 'Cleanup'].includes(code) ? code : 'Transport';
    this.mayHaveCommitted = attempted && MUTATIONS.has(operation);
    this.mayHavePublished = attempted && PUBLICATIONS.has(operation);
    this.retryAllowed = false;
  }
}
export class PublicLedgerRejection extends Error {
  constructor(operation, code) {
    super('CP03 public ledger returned rejection'); this.name = 'PublicLedgerRejection';
    this.operation = operation; this.code = code;
    // A fixed CLI error alone is not an independent observation of durable state.
    this.stateInvarianceEstablished = false; this.retryAllowed = false;
    this.mayHaveCommitted = MUTATIONS.has(operation);
    this.mayHavePublished = PUBLICATIONS.has(operation);
  }
}
function input(ok) { if (!ok) throw new PublicLedgerInputError(); }
function output(ok) { if (!ok) throw new Error('invalid public result'); }
function publicPath(value) {
  input(typeof value === 'string' && path.isAbsolute(value) && !value.includes('\0') &&
    Buffer.byteLength(value, 'utf8') <= 4095 && Buffer.from(value, 'utf8').toString('utf8') === value);
  return path.normalize(value);
}
function inputInteger(value, maximum = U64) {
  input(typeof value === 'bigint' && value >= 0n && value <= maximum); return value.toString();
}
function inputBytes(value, length, field = false) {
  input(Buffer.isBuffer(value) && value.length === length);
  if (field) for (let i = 0; i < length; i += 8) input(value.readBigUInt64LE(i) < P);
  return value.toString('hex');
}
function object(value, keys) {
  output(value !== null && typeof value === 'object' && !Array.isArray(value));
  output(Object.keys(value).sort().join(',') === [...keys].sort().join(','));
}
function decimal(value, max = U64) {
  output(typeof value === 'string' && value.length <= 20 && /^(0|[1-9][0-9]*)$/.test(value));
  const n = BigInt(value); output(n <= max); return n;
}
function hex(value, size, field = false) {
  output(typeof value === 'string' && value.length === size * 2 && /^[0-9a-f]+$/.test(value));
  const b = Buffer.from(value, 'hex');
  if (field) for (let i = 0; i < size; i += 8) output(b.readBigUInt64LE(i) < P);
  return b;
}
function parseJson(bytes) {
  output(Buffer.isBuffer(bytes) && bytes.length > 1 && bytes.length <= OUTPUT_BYTES);
  const text = bytes.toString('utf8'); output(Buffer.from(text, 'utf8').equals(bytes));
  const value = JSON.parse(text);
  // CLI values have ASCII keys, decimal/hex strings and Boolean/array values only.
  // Exact compact roundtrip rejects duplicate keys, suffixes, escapes and extra lines.
  output(JSON.stringify(value) + '\n' === text); return value;
}
function sameInode(a, b) {
  return ['dev', 'ino', 'size', 'mode', 'uid', 'gid', 'mtimeNs', 'ctimeNs'].every(k => a[k] === b[k]);
}
function inspectBinary(fd, binary, expected) {
  const before = fs.fstatSync(fd, {bigint: true});
  if (!before.isFile() || before.size <= 0n || before.size > BigInt(BINARY_BYTES)) throw new Error('binary shape');
  const hash = crypto.createHash('sha256'), chunk = Buffer.alloc(65536);
  let at = 0;
  while (at < Number(before.size)) {
    const n = fs.readSync(fd, chunk, 0, Math.min(chunk.length, Number(before.size) - at), at);
    if (n === 0) throw new Error('binary read');
    if (at === 0 && (n < 4 || !chunk.subarray(0, 4).equals(Buffer.from([127, 69, 76, 70])))) throw new Error('binary type');
    hash.update(chunk.subarray(0, n)); at += n;
  }
  const after = fs.fstatSync(fd, {bigint: true}), named = fs.lstatSync(binary, {bigint: true});
  if (!sameInode(before, after) || !sameInode(after, named) || hash.digest('hex') !== expected) throw new Error('binary changed');
}
function openBinary(binary, expected) {
  const fd = fs.openSync(binary, fs.constants.O_RDONLY | fs.constants.O_NOFOLLOW | fs.constants.O_NONBLOCK);
  try { inspectBinary(fd, binary, expected); return fd; }
  catch (error) { try { fs.closeSync(fd); } catch {} throw error; }
}

// Call once with a root-installed actual build approval. Never derive this object
// from a transaction, RPC request, server scan record or wallet-private packet.
export function preparePublicLedger(config) {
  input(config !== null && typeof config === 'object' && !Array.isArray(config));
  const keys = Object.keys(config);
  input(['binaryPath', 'binarySha256', 'chain', 'dbPath'].every(key => keys.includes(key)) &&
    keys.every(key => ['binaryPath', 'binarySha256', 'chain', 'dbPath', 'blockVersion', 'retention'].includes(key)));
  const blockVersion = config.blockVersion === undefined ? 3 : config.blockVersion;
  const retention = config.retention === undefined ? 'archive' : config.retention;
  input((blockVersion === 3 || blockVersion === 4) && ['archive', 'retain'].includes(retention));
  input(retention !== 'retain' || blockVersion === 4);
  const binary = publicPath(config.binaryPath), db = publicPath(config.dbPath);
  input(typeof config.binarySha256 === 'string' && /^[0-9a-f]{64}$/.test(config.binarySha256));
  const expected = config.binarySha256, chain = inputBytes(config.chain, 32);
  let preparedFd;
  try { preparedFd = openBinary(binary, expected); }
  catch { throw new PublicLedgerOperationalError('prepare', 'Binary'); }
  finally {
    if (preparedFd !== undefined) {
      try { fs.closeSync(preparedFd); } catch { throw new PublicLedgerOperationalError('prepare', 'Cleanup'); }
    }
  }
  function head(value) {
    object(value, ['schema', 'chain', 'genesis_id', 'height', 'block_id', 'leaf_count', 'root_le', 'fee_escrow', 'unconsumed_liabilities',
      ...(blockVersion === 4 ? ['block_version'] : [])]);
    output(value.schema === 'CP03-LEDGER-CLI-01' && value.chain === chain);
    if (blockVersion === 4) output(value.block_version === '4');
    const fees = decimal(value.fee_escrow, MAX), liabilities = decimal(value.unconsumed_liabilities, MAX);
    output(fees + liabilities <= MAX);
    return Object.freeze({chain: hex(value.chain, 32), genesisId: hex(value.genesis_id, 64),
      height: decimal(value.height), blockId: hex(value.block_id, 64), leafCount: decimal(value.leaf_count, LEAVES),
      root: hex(value.root_le, 64, true), feeEscrow: fees, unconsumedLiabilities: liabilities,
      ...(blockVersion === 4 ? {blockVersion: 4} : {})});
  }
  function run(operation, arguments_, decode) {
    let fd, child, attempted = false, result, failure;
    try {
      fd = openBinary(binary, expected);
      attempted = true;
      child = spawnSync('/proc/self/fd/3', arguments_, {
        stdio: ['ignore', 'pipe', 'pipe', fd], cwd: '/', env: ENV,
        timeout: WALL_MS, maxBuffer: OUTPUT_BYTES, killSignal: 'SIGKILL',
      });
      // Keep the descriptor open through actual status/output validation and rehash.
      inspectBinary(fd, binary, expected);
      if (child.error || child.signal !== null || !Number.isInteger(child.status) ||
          !Buffer.isBuffer(child.stdout) || !Buffer.isBuffer(child.stderr) ||
          child.stdout.length > OUTPUT_BYTES || child.stderr.length > OUTPUT_BYTES) {
        throw new PublicLedgerOperationalError(operation, 'Transport', attempted);
      }
      if (child.status === 1 && child.stdout.length === 0) {
        const text = child.stderr.toString('ascii');
        const match = /^CP03_LEDGER_ERROR ([A-Za-z]+)\n$/.exec(text);
        if (match && CLI_ERRORS.has(match[1]) && child.stderr.equals(Buffer.from(text, 'ascii'))) {
          if (OPERATIONAL.has(match[1])) throw new PublicLedgerOperationalError(operation, match[1], attempted);
          throw new PublicLedgerRejection(operation, match[1]);
        }
      }
      if (child.status !== 0 || child.stderr.length !== 0) throw new PublicLedgerOperationalError(operation, 'Output', attempted);
      try { result = decode(parseJson(child.stdout)); }
      catch { throw new PublicLedgerOperationalError(operation, 'Output', attempted); }
    } catch (error) {
      failure = error instanceof PublicLedgerOperationalError || error instanceof PublicLedgerRejection
        ? error : new PublicLedgerOperationalError(operation, attempted ? 'Transport' : 'Binary', attempted);
    } finally {
      // All streams are PUBLIC, nevertheless never forward raw CLI/provider diagnostics.
      child?.stdout?.fill(0); child?.stderr?.fill(0);
      if (fd !== undefined) {
        try { fs.closeSync(fd); }
        catch { failure = new PublicLedgerOperationalError(operation, 'Cleanup', attempted); }
      }
    }
    if (failure) throw failure;
    return result;
  }
  function bodies(files) {
    input(Array.isArray(files) && files.length >= (blockVersion === 4 ? 0 : 1) &&
      files.length <= (blockVersion === 4 ? 128 : 16));
    return files.map(publicPath);
  }
  return Object.freeze({
    init: genesisFile => run('init', [retention === 'retain' ? 'init-retain' : 'init', db, chain, publicPath(genesisFile)], head),
    head: () => run('head', ['head', db, chain], head),
    admit: files => run('admit', ['admit', db, chain, ...bodies(files)], head),
    replay: (headerFile, files) => run('replay', ['replay', db, chain, publicPath(headerFile), ...bodies(files)], head),
    rollback: expectedTip => run('rollback', ['rollback', db, chain, inputBytes(expectedTip, 64)], head),
    membership: (index, anchor) => {
      input(anchor !== null && typeof anchor === 'object');
      const i = inputInteger(index, LEAVES - 1n), count = inputInteger(anchor.count, LEAVES);
      input(anchor.count > 0n && index < anchor.count); const root = inputBytes(anchor.root, 64, true);
      return run('membership', ['membership', db, chain, i, count, root], value => {
        object(value, ['schema', 'index', 'count', 'origin_le', 'cm_le', 'root_le', 'siblings_le']);
        output(value.schema === 'CP03-MEMBERSHIP-01' && value.index === i && value.count === count && value.root_le === root);
        output(Array.isArray(value.siblings_le) && value.siblings_le.length === 40);
        return Object.freeze({index: decimal(value.index, LEAVES - 1n), count: decimal(value.count, LEAVES),
          origin: hex(value.origin_le, 64, true), cm: hex(value.cm_le, 64, true), root: hex(value.root_le, 64, true),
          siblings: Object.freeze(value.siblings_le.map(x => hex(x, 64, true)))});
      });
    },
    spent: nf => run('spent', ['spent', db, chain, inputBytes(nf, 64, true)], value => {
      object(value, ['schema', 'spent']); output(value.schema === 'CP03-SPENT-01' && typeof value.spent === 'boolean');
      return value.spent;
    }),
    scan: outputFile => run('scan', ['scan', db, chain, publicPath(outputFile)], head),
    checkScan: (genesisFile, scanFile, endpoint, outputFile) => {
      input(endpoint !== null && typeof endpoint === 'object');
      const height = inputInteger(endpoint.height), id = inputBytes(endpoint.blockId, 64), genesis = inputBytes(endpoint.genesisId, 64);
      return run('check-scan', ['check-scan', chain, publicPath(genesisFile), publicPath(scanFile), height, id, publicPath(outputFile)], value => {
        object(value, ['schema', 'validity', 'chain', 'genesis_id', 'height', 'block_id', 'leaf_count']);
        output(value.schema === 'CP03-CHECKED-SCAN-01' && value.validity === 'delegated-endpoint-relative' &&
          value.chain === chain && value.height === height && value.block_id === id && value.genesis_id === genesis);
        return Object.freeze({chain: hex(value.chain, 32), genesisId: hex(value.genesis_id, 64),
          height: decimal(value.height), blockId: hex(value.block_id, 64), leafCount: decimal(value.leaf_count, LEAVES),
          validity: 'delegated-endpoint-relative'});
      });
    },
  });
}
