// Fixed installed PRIVATE07 bridge. Secrets use stdin only, never argv/files/hashes.
// Returned proof is a public artifact; fresh ledger/public verification is mandatory.
import * as fs from 'node:fs';
import * as path from 'node:path';
import * as crypto from 'node:crypto';
import {spawnSync} from 'node:child_process';
import {fileURLToPath} from 'node:url';
import {consumePrivatePacket, publicPayment} from './payments.mjs';
import {WalletInputError} from './codec.mjs';
import {WalletOperationalError} from './keys.mjs';

const ROOT = fileURLToPath(new URL('../../', import.meta.url));
const AREA = path.join(ROOT, 'experiments/compact-all-payments-v3');
const PARENT = path.join(AREA, 'private04-proposal/next07/private_parent.py');
const PARENT_SHA = "b5dc012a774024f4f1c5ab44f382cbe963ec1746b42c8b3f0cb9824c979f68c9";
const installed = new WeakMap();
function need(condition) { if (!condition) throw new WalletInputError(); }
function digest(bytes) { return crypto.createHash('sha256').update(bytes).digest('hex'); }
function readPublic(file, cap) {
  let fd;
  try {
    fd = fs.openSync(file, fs.constants.O_RDONLY | fs.constants.O_NONBLOCK | fs.constants.O_NOFOLLOW);
    const before = fs.fstatSync(fd, {bigint: true}); need(before.isFile() && before.size <= BigInt(cap));
    const chunks = []; let size = 0;
    for (;;) {
      const chunk = Buffer.alloc(Math.min(65536, cap + 1 - size));
      const n = fs.readSync(fd, chunk, 0, chunk.length, null);
      if (n === 0) break;
      size += n; need(size <= cap); chunks.push(chunk.subarray(0, n));
    }
    const after = fs.fstatSync(fd, {bigint: true});
    need(['dev', 'ino', 'size', 'mtimeNs', 'ctimeNs'].every(k => before[k] === after[k]));
    return Buffer.concat(chunks, size);
  } finally { if (fd !== undefined) fs.closeSync(fd); }
}
function repositoryPath(relative) {
  need(typeof relative === 'string' && !path.isAbsolute(relative) && !relative.split('/').includes('..'));
  const result = path.resolve(ROOT, relative); need(result.startsWith(ROOT)); return result;
}
function sha(value) { need(typeof value === 'string' && /^[0-9a-f]{64}$/.test(value)); return value; }
function label(value) { need(typeof value === 'string' && /^[a-z0-9_-]+$/.test(value)); return value; }

// Only an operator supplies this path/hash after actual build, inspect and boundary gates.
// A transaction or recipient must never provide an approval or program selector.
export function installPrivateProver(approvalRelativePath, approvalSha256) {
  try {
    const approvalPath = repositoryPath(approvalRelativePath), raw = readPublic(approvalPath, 65536);
    need(digest(raw) === sha(approvalSha256) && digest(readPublic(PARENT, 131072)) === PARENT_SHA);
    const approval = JSON.parse(raw.toString('utf8'));
    need(approval.format === 'CP-PRIVATE-OPERATOR07');
    const runtimePath = repositoryPath(approval.runtime_receipt), runtimeRaw = readPublic(runtimePath, 4 * 1024 * 1024);
    need(digest(runtimeRaw) === sha(approval.runtime_receipt_sha256));
    const runtime = JSON.parse(runtimeRaw.toString('utf8'));
    need(runtime.mode === 'inspect' && runtime.process_exit === 0 && runtime.wrapper_exit === 0 &&
      runtime.timeout === false && runtime.source_pins_unchanged === true && runtime.runtime_pins_unchanged === true &&
      runtime.manifest_sha256 === approval.source_manifest_sha256 && runtime.binary_sha256 === approval.binary_sha256);
    const python = runtime.runtime_details.python.path;
    need(typeof python === 'string' && path.isAbsolute(python));
    const pythonSha = sha(runtime.runtime_before[python]);
    need(digest(readPublic(python, 128 * 1024 * 1024)) === pythonSha);
    // Match the approved tool environment. It contains no PYTHON*/LD_* overrides.
    const env = {...runtime.controlled_environment};
    need(Object.entries(env).every(([k, v]) => !k.startsWith('LD_') && !k.startsWith('PYTHON') && typeof v === 'string'));
    const token = Object.freeze({type: 'CP03-installed-private-prover'});
    installed.set(token, {approvalPath, approvalSha256, approval, python, pythonSha, env}); return token;
  } catch { throw new WalletOperationalError(); }
}

export async function provePayment(prover, payment, attemptLabel) {
  const approved = installed.get(prover); need(!!approved); label(attemptLabel);
  const expected = publicPayment(payment);
  return consumePrivatePacket(payment, packet => {
    let child;
    try {
      need(digest(readPublic(approved.approvalPath, 65536)) === approved.approvalSha256 &&
        digest(readPublic(PARENT, 131072)) === PARENT_SHA &&
        digest(readPublic(approved.python, 128 * 1024 * 1024)) === approved.pythonSha);
      child = spawnSync(approved.python, ['-I', '-B', PARENT, '--approval', approved.approvalPath,
        '--label', attemptLabel, '--public-label', attemptLabel], {
        cwd: ROOT, env: approved.env, input: packet, timeout: 180000, maxBuffer: 65536, killSignal: 'SIGKILL',
      });
      need(!child.error && child.signal === null && child.status === 0 &&
        Buffer.isBuffer(child.stdout) && Buffer.isBuffer(child.stderr) && child.stderr.length === 0);
      const summary = JSON.parse(child.stdout.toString('utf8'));
      const wanted = {format: 'CP-ALL-PRIVATE-PARENT07', label: attemptLabel,
        process_exit: 0, wrapper_exit: 0, fresh_public_verification_still_required: true};
      need(Object.keys(summary).sort().join(',') === Object.keys(wanted).sort().join(',') &&
        Object.keys(wanted).every(k => summary[k] === wanted[k]));
      const receiptPath = path.join(AREA, 'evidence', attemptLabel + '.json');
      const receiptRaw = readPublic(receiptPath, 8 * 1024 * 1024), receipt = JSON.parse(receiptRaw.toString('utf8'));
      need(receipt.format === wanted.format && receipt.mode === 'prove-private' && receipt.label === attemptLabel &&
        receipt.public_label === attemptLabel && receipt.process_exit === 0 && receipt.wrapper_exit === 0 &&
        receipt.timeout === false && receipt.source_pins_unchanged === true && receipt.runtime_pins_unchanged === true &&
        receipt.private_input_written_or_hashed === false && receipt.unchecked_child_output_persisted === false &&
        receipt.fresh_public_verification_still_required === true && receipt.arity === expected.arity &&
        receipt.binary_sha256 === approved.approval.binary_sha256 &&
        receipt.manifest_sha256 === approved.approval.source_manifest_sha256 &&
        receipt.approved_runtime_receipt_sha256 === approved.approval.runtime_receipt_sha256);
      const directory = path.join(AREA, 'public', attemptLabel);
      need(fs.readdirSync(directory).sort().join(',') === 'manifest.json,proof.bin,statement.bin');
      const statement = readPublic(path.join(directory, 'statement.bin'), 528);
      const proof = readPublic(path.join(directory, 'proof.bin'), 2097152);
      const manifest = readPublic(path.join(directory, 'manifest.json'), 65536);
      need(statement.equals(expected.statement) && proof.length > 0 &&
        receipt.public_artifacts['statement.bin'] === digest(statement) &&
        receipt.public_artifacts['proof.bin'] === digest(proof) && receipt.public_artifacts['manifest.json'] === digest(manifest));
      need(digest(readPublic(approved.approvalPath, 65536)) === approved.approvalSha256 &&
        digest(readPublic(PARENT, 131072)) === PARENT_SHA &&
        digest(readPublic(approved.python, 128 * 1024 * 1024)) === approved.pythonSha);
      return {proof, public_directory: directory, parent_receipt: receiptPath,
        parent_receipt_sha256: digest(receiptRaw), fresh_public_verification_still_required: true};
    } catch { throw new WalletOperationalError(); }
    finally { child?.stdout?.fill(0); child?.stderr?.fill(0); }
  });
}
