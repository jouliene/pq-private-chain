"""Public codec and proof checks for the isolated FTL1/SLG1 registration pair."""
from hashlib import sha256
from pathlib import Path
import struct
import subprocess
import sys
import time

EX = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(EX / 'atomic-swap'))
import swap_wire as sw

LEG, FRAME, BUNDLE = b'FTL1\x01', b'FTF1\x01', b'FTB1\x01'
P = 2**64 - 2**32 + 1
WORDS = struct.Struct('<38Q')
PROOF_LIMIT = 239976


def proof_context(network, tip, count, receipts):
    sw.require(len(network) == len(tip) == 32 and 0 < count <= 4**20 and len(receipts) == sw.CT_PAIR,
               'invalid proof context')
    return sha256(b'FTL1/proof-context/v1\0' + network + tip + struct.pack('<Q', count) + receipts).digest()


def candidate_parts(leg):
    sw.require(leg.startswith(LEG) and len(leg) >= 9 + WORDS.size + sw.CT_PAIR, 'FTL1 packet')
    n, = struct.unpack_from('<I', leg, 5)
    sw.require(0 < n <= PROOF_LIMIT and len(leg) == 9 + WORDS.size + n + sw.CT_PAIR, 'FTL1 proof length')
    words = WORDS.unpack_from(leg, 9)
    sw.require(all(x < P for x in words) and words[4] < 2**32 and all(x < 2**32 for x in words[26:34]),
               'noncanonical public statement')
    return words, leg[9+WORDS.size:-sw.CT_PAIR], leg[-sw.CT_PAIR:]


def candidate_fields(leg):
    return candidate_parts(leg)[0]


def encode_leg(words, proof, receipts):
    leg = LEG + struct.pack('<I', len(proof)) + WORDS.pack(*words) + proof + receipts
    candidate_parts(leg)
    return leg


def assemble(network, terms, expiry, payer, legs, signatures):
    sw.digest(network, terms, expiry, payer, legs)
    sw.require(len(signatures) == 2 and all(len(s) == sw.SIG for s in signatures), 'signature widths')
    frames = [FRAME + struct.pack('<BBI', i, payer, expiry) + network + terms + sha256(legs[1-i]).digest()
              + signatures[i] + leg for i, leg in enumerate(legs)]
    raw = BUNDLE + b''.join(struct.pack('<I', len(f)) + f for f in frames)
    split(raw)
    return raw


def read_frame(f):
    sw.require(sw.HEADER + sw.SIG < len(f) <= sw.LIMIT and f.startswith(FRAME), 'mixed frame header/size')
    side, payer, expiry = struct.unpack_from('<BBI', f, 5)
    sw.require(side in (0, 1) and payer in (0, 1) and expiry and f[43:75] != bytes(32), 'mixed frame fields')
    leg = f[sw.HEADER+sw.SIG:]
    if side == 0:
        candidate_parts(leg)
    else:
        sw.leg_shape(leg)
    return sw.Frame(side, payer, expiry, f[11:43], f[43:75], f[75:107], f[107:sw.HEADER+sw.SIG], leg)


def split(raw):
    sw.require(raw.startswith(BUNDLE) and len(raw) <= sw.MAX_BUNDLE, 'mixed bundle shape')
    offset = len(BUNDLE)
    frames = []
    for index in (0, 1):
        sw.require(offset + 4 <= len(raw), 'missing mixed frame')
        n, = struct.unpack_from('<I', raw, offset)
        offset += 4
        sw.require(sw.HEADER + sw.SIG < n <= sw.LIMIT and offset + n <= len(raw), 'mixed frame length')
        frame = read_frame(raw[offset:offset+n])
        sw.require(frame.side == index, 'mixed frame order')
        frames.append(frame)
        offset += n
    a, b = frames
    sw.require(offset == len(raw) and (a.network,a.terms,a.expiry,a.payer) == (b.network,b.terms,b.expiry,b.payer)
               and a.other == sha256(b.leg).digest() and b.other == sha256(a.leg).digest(), 'unmatched mixed pair')
    return tuple(frames)


def engine_call(engine, shape, mode, payload):
    """The fresh child sees only its approved executable, public shape, system libraries and pipes."""
    sw.require(mode in ('prove', 'verify'), 'unknown engine mode')
    cmd = ['bwrap', '--unshare-all', '--die-with-parent', '--new-session', '--cap-drop', 'ALL', '--clearenv',
           '--proc', '/proc', '--dev', '/dev']
    for path in ('/usr','/lib','/lib64','/etc/ld.so.cache'):
        cmd += ['--ro-bind', path, path]
    cmd += ['--ro-bind', str(Path(engine).resolve(strict=True)), '/engine', '--ro-bind',
            str(Path(shape).resolve(strict=True)), '/shape', '--remount-ro', '/', '--chdir', '/',
            '--', '/usr/bin/time', '-f', 'FTL-METER %U %S %M %e', '/engine', mode, '/shape']
    before = time.perf_counter()
    completed = subprocess.run(cmd, input=payload, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    isolated_wall = time.perf_counter()-before
    if completed.returncode:
        raise ValueError(f'{mode} rejected (exit {completed.returncode})')
    fields = completed.stderr.split()
    sw.require(len(fields) == 5 and fields[0] == b'FTL-METER', 'invalid native role timing')
    user, system, rss, wall = fields[1:]
    metrics = dict(wall_s=float(wall), isolated_wall_s=round(isolated_wall, 6), user_s=float(user),
                   system_s=float(system), max_rss_KiB=int(rss))
    return completed.stdout, metrics


def verify_candidate(engine, shape, leg, network, tip, count, expected_aux_root, params):
    from funded_projection import receipt_hash
    words, proof, receipts = candidate_parts(leg)
    sw.require(struct.pack('<4Q', *words[34:]) == expected_aux_root and receipt_hash(params, receipts) == words[22:26],
               'funded root or ordered ciphertext digest differs')
    context = proof_context(network, tip, count, receipts)
    result, measurement = engine_call(engine, shape, 'verify', context + WORDS.pack(*words) + proof)
    sw.require(result == b'', 'unexpected verifier output')
    return words, measurement


def validate_pair(raw, engine, shape, network, height, tip, count, expected_aux_root, params, verifier, metrics=None):
    """Verify complete public proofs and joint signatures. Caller owns branch/anchor/spentness and state."""
    import swap_wallet
    a, b = split(raw)
    sw.require(a.network == network and height <= a.expiry, 'network or expiry')
    words, candidate_metric = verify_candidate(engine, shape, a.leg, network, tip, count, expected_aux_root, params)
    def digest_at(index):
        return struct.pack('<4Q', *words[index:index+4])
    receipts = a.leg[-sw.CT_PAIR:]
    first = swap_wallet.Effect(digest_at(0), words[4], (digest_at(5),digest_at(9)), (digest_at(13),digest_at(17)),
                               words[21], (receipts[:1792], receipts[1792:]), struct.pack('<8I', *words[26:34]))
    if metrics is not None:
        from wallet_sync import role_sample
        before = role_sample(verifier)
        start = time.perf_counter()
    second = swap_wallet.verify(verifier, b.leg)
    if metrics is not None:
        elapsed = time.perf_counter()-start
        after = role_sample(verifier)
        metrics.update(candidate=candidate_metric, released=dict(wall_s=round(elapsed, 6),
                       cpu_s=round(after[0]-before[0], 4), max_rss_KiB=after[1]))
    effects = (first, second)
    sw.require(bytes(32) not in first.cms and first.public != bytes(32) and second.public != bytes(32)
               and first.public != second.public and len({n for e in effects for n in e.nfs}) == 4
               and len({c for e in effects for c in e.cms}) == 4, 'duplicate or invalid swap effects')
    signed = sw.digest(network, a.terms, a.expiry, a.payer, (a.leg, b.leg))
    for frame, effect in zip((a,b), effects, strict=True):
        sw.require(effect.fee == (3 if frame.side == a.payer else 0) and
                   verifier.call(b'V' + effect.public + signed + frame.signature) == b'1', 'fee or owner authorization')
    return (a,b), effects


def physical_frames(raw):
    split(raw)
    n, = struct.unpack_from('<I', raw, len(BUNDLE))
    start = len(BUNDLE) + 4
    return raw[start:start+n], raw[start+n+4:]
