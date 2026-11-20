"""Read physical SWF1 frames and verify SWP1 authorization using two independent providers."""
from dataclasses import dataclass
from hashlib import sha256
from pathlib import Path
import struct
import subprocess
import sys

HERE = Path(__file__).resolve().parent
MANAGED = HERE.parents[1] / "managed-assets/review"
sys.path.insert(0,str(MANAGED))
from events import Event, ZERO, ast1


def hash_bytes(data):
    return sha256(data).digest()


def opposite(data):
    return bytes([data[0] ^ 1]) + data[1:]


def joint(network, terms, expiry, payer, legs):
    return hash_bytes(b"SWP1/joint-authorization/v1\0" + network + terms +
                      struct.pack("<IB", expiry, payer) + b"".join(map(hash_bytes, legs)))


def encode_pair(frames):
    return b"SWB1\x01" + b"".join(struct.pack("<I",len(f)) + f for f in frames)


def decode_pair(raw):
    assert raw[:5] == b"SWB1\x01" and len(raw) <= 5 + 2 * (4 + 262144)
    frames = []
    pos = 5
    for _ in range(2):
        length, = struct.unpack_from("<I",raw,pos)
        pos += 4
        assert 0 < length <= min(262144,len(raw)-pos)
        frames.append(raw[pos:pos+length])
        pos += length
    assert pos == len(raw)
    return tuple(frames)


@dataclass(frozen=True)
class Frame:
    encoded: bytes
    side: int
    payer: int
    expiry: int
    network: bytes
    terms: bytes
    partner_digest: bytes
    signature: bytes
    leg: bytes
    key: bytes
    effect: Event


def read_frame(raw, verifier, roots):
    assert raw[:5] == b"SWF1\x01" and 17195 < len(raw) <= 262144
    side,payer,expiry = struct.unpack_from("<BBI",raw,5)
    assert side in (0,1) and payer in (0,1) and expiry > 0
    net,terms,other,sig = raw[11:43],raw[43:75],raw[75:107],raw[107:17195]
    assert terms != ZERO and len(sig) == 17088
    leg = raw[17195:]
    assert leg[:5] == b"SLG1\x01"
    proof_bytes, = struct.unpack_from("<I",leg,5)
    end = 9 + proof_bytes
    assert proof_bytes > 280 and len(leg) == end + 3584
    count,*words = struct.unpack_from("<35Q",leg,end-280)
    assert count == 34 and all(w < ast1.P for w in words)
    pi = leg[end-272:end]
    ciphertexts = leg[end:]
    assert ast1.reference(roots,["--ciphertext-digests"],ciphertexts) == [pi[176:208].hex()]
    assert words[4] < 2**32 and words[21] == (3 if side == payer else 0)
    assert all(w < 2**32 for w in words[26:])
    key = struct.pack("<8I", *words[26:])
    assert verifier.call(leg) == b"1" + pi[:36] + pi[40:176] + ciphertexts + key
    effect = Event(hash_bytes(raw),0,b"",0,ZERO,words[4],pi[:32],(pi[40:72],pi[72:104]),
                   (pi[104:136],pi[136:168]),words[21],ZERO,0,ciphertexts)
    assert len(set(effect.nullifiers)) == len(set(effect.commitments)) == 2 and ZERO not in effect.commitments
    return Frame(raw,side,payer,expiry,net,terms,other,sig,leg,key,effect)


class Reader:
    def __init__(self, legacy, swap):
        self.legacy = legacy
        self.role = swap
        self.network = legacy.network
        self.frames = {}
        self.groups = {}
        self.signatures = []
        self.cases = {}
        self.proof_calls = 0

    def packet(self, raw):
        if raw[:5] != b"SWF1\x01":
            return self.legacy.packet(raw)
        f = read_frame(raw,self.role,self.legacy.roots)
        self.proof_calls += 1
        assert f.network == self.network
        assert self.frames.setdefault(f.effect.txid,f) == f
        return f.effect

    def validate_pair(self, first, second, height=None):
        fs = first,second
        legs = tuple(f.leg for f in fs)
        assert (first.side,second.side) == (0,1) and first.key != second.key
        assert (first.network,first.terms,first.expiry,first.payer) == (second.network,second.terms,second.expiry,second.payer)
        assert tuple(f.partner_digest for f in fs) == (hash_bytes(legs[1]), hash_bytes(legs[0]))
        assert height is None or height <= first.expiry
        digest = joint(self.network,first.terms,first.expiry,first.payer,legs)
        for f in fs:
            envelope = f.key + digest + f.signature
            assert self.role.call(b"V"+envelope) == b"1"
            self.signatures.append(envelope)
        raw = encode_pair([f.encoded for f in fs])
        bid = hash_bytes(raw)
        row = dict(id=bid.hex(),leg_txids=[f.effect.txid.hex() for f in fs],complete_upload_B=len(raw),
                   block_frame_B=[len(f.encoded) for f in fs],complete_in_block_B=len(raw)-5,
                   leg_B=[len(x) for x in legs],proof_B=[len(x)-3593 for x in legs],
                   signature_B=2*17088,receipt_B=4*1792,expiry=first.expiry,payer=first.payer,
                   fee_by_leg=[f.effect.fee for f in fs])
        assert self.groups.setdefault(bid,row) == row
        self.cases.setdefault(bid,fs)
        return bid

    def validate_block(self, slots, height):
        count = 0
        it = iter(slots)
        for leg in it:
            if leg.txid not in self.frames:
                continue
            second = next(it,None)
            assert second is not None and second.txid in self.frames
            self.validate_pair(self.frames[leg.txid],self.frames[second.txid],height)
            count += 1
        return count

    def public_controls(self):
        rows=[]
        for ident,frames in self.cases.items():
            for f in frames:
                raw=f.leg
                # The registered managed role also contains the original AST1 verification path.
                for magic in (b"SLG1",b"AST1",b"MNG1"):
                    assert self.legacy.role.call(magic+raw[4:])==b"0"
                changed=bytearray(raw)
                changed[-1]^=1
                assert self.role.call(changed)==b"0"
                key_word=bytearray(raw)
                key_word[len(raw)-3584-64]^=1
                assert self.role.call(key_word)==b"0"
                rows.append(dict(group=ident.hex(),side=f.side,ordinary_role_denials=3,
                                 receipt_mismatch_rejected=True,proof_key_substitution_rejected=True))
        return rows

    def verify_independent(self, node):
        cases = []
        for fs in self.cases.values():
            a,b = fs
            legs = [a.leg,b.leg]
            def message(**kw):
                args = dict(network=self.network,terms=a.terms,expiry=a.expiry,payer=a.payer,legs=legs)
                return joint(**(args | kw))
            variants = {"network":message(network=opposite(self.network)), "terms":message(terms=opposite(a.terms)),
                        "expiry":message(expiry=a.expiry^1), "payer":message(payer=1-a.payer),
                        "order":message(legs=legs[::-1])}
            for i, leg in enumerate(legs):
                pi_end = len(leg)-3584
                for name, pos in (("proof",9),("anchor",pi_end-272),("first_nullifier",pi_end-272+40),
                                  ("first_commitment",pi_end-272+104),("second_commitment",pi_end-272+136),
                                  ("fee",pi_end-272+168),("one_time_key",pi_end-64),
                                  ("first_receipt",pi_end),("second_receipt",pi_end+1792)):
                    changed = bytearray(leg)
                    changed[pos] ^= 1
                    alter = list(legs)
                    alter[i] = changed
                    variants[f"leg_{i}_{name}"] = message(legs=alter)
            for f,other in (fs,fs[::-1]):
                cases.extend((name,f.key+msg+f.signature) for name,msg in variants.items())
                cases.append(("partner_key",other.key+message()+f.signature))
                cases.append(("signature",f.key+message()+opposite(f.signature)))
        good = list(dict.fromkeys(self.signatures))
        assert good and cases
        blob = b"".join(good + [row for _,row in cases])
        answer = subprocess.check_output([node,MANAGED/"verify_slh.mjs"],input=blob,timeout=90)
        assert answer == b"1"*len(good) + b"0"*len(cases)
        return dict(valid_distinct=len(good),changed_authorizations_rejected=len(cases),
                    tested_changes=sorted({name for name,_ in cases}),provider="Node 24.22.1 / OpenSSL 3.5.9")
