"""Private AST1 note inventory, admission requests and accounting for the ordinary wallet."""
from dataclasses import dataclass
import hashlib
from itertools import combinations
import struct

FEE = 3
MAX_AMOUNT = (1 << 62) - 1
ZERO = bytes(32)


def valid_id(value):
    return isinstance(value, bytes) and len(value) == 32 and all(x < 128 for x in value[7::8])


def parse_asset(text):
    if text == "native":
        return ZERO
    if len(text) != 64:
        raise ValueError("asset must be a 32-byte hexadecimal ID or native")
    value = bytes.fromhex(text)
    if not valid_id(value):
        raise ValueError("asset ID outside the registered encoding")
    return value


def issuance_id(network, first_nf):
    if len(network) != 32 or len(first_nf) != 32:
        raise ValueError("invalid network or first nullifier")
    digest = bytearray(hashlib.sha256(b"AST1/issue-id/v1\0" + network + first_nf).digest())
    for index in (7, 15, 23, 31):
        digest[index] &= 127
    if digest == ZERO:
        raise ValueError("first input derives the reserved zero issuance ID")
    return bytes(digest)


@dataclass(frozen=True)
class Request:
    native: int
    asset: bytes
    token: int
    supply: int = 0

    def __post_init__(self):
        if not valid_id(self.asset) or any(type(n) != int or not 0 <= n <= MAX_AMOUNT
                                           for n in (self.native, self.token, self.supply)):
            raise ValueError("invalid asset ID or amount outside the unsigned 62-bit range")
        if self.supply:
            if self.native or self.asset != ZERO or self.supply != self.token:
                raise ValueError("issuance requires a positive supply and native-only inputs")
        elif not (self.native or self.token) or (self.asset == ZERO) != (self.token == 0):
            raise ValueError("supply a positive native payment or a positive amount of the selected asset")

    @classmethod
    def issue(cls, supply):
        return cls(0, ZERO, supply, supply)

    @classmethod
    def from_row(cls, row):
        return cls(row["amount"], row["asset"], row["token"], row["supply"])

    def encode(self, resolved_id):
        return struct.pack("<QQ32sQ", self.native, self.token, resolved_id, self.supply)


def default_id(address, request):
    label = "issue-" if request.supply else "pay-"
    return label + hashlib.sha256(b"AST1/devnet/local-intent/v1\0" + address +
                                  request.encode(request.asset)).hexdigest()[:32]


def change_for(request, native_total, token_total):
    native_change = native_total - request.native - FEE
    token_change = token_total + request.supply - request.token
    if 0 <= native_change <= MAX_AMOUNT and 0 <= token_change <= MAX_AMOUNT:
        return native_change, token_change
    return None


def permitted(request, asset):
    if request.supply:
        return asset == ZERO
    return request.asset == ZERO or asset in (ZERO, request.asset)


def select_amounts(rows, request, exclude):
    eligible = [(cm.hex(), n, asset, t) for cm, n, asset, t in rows
                if permitted(request, asset) and not exclude(cm.hex())]
    # Try smaller input counts first and prefer native-only notes within a count.
    # Any positive asset balance in mixed inputs must fit in the change output.
    eligible.sort(key=lambda row: row[2] != ZERO)
    for width in (1, 2):
        for group in combinations(eligible, width):
            if len({row[2] for row in group if row[2] != ZERO}) > 1:
                continue
            if change_for(request, sum(row[1] for row in group), sum(row[3] for row in group)) is not None:
                return tuple(row[0] for row in group)
    raise ValueError("insufficient compatible funds within two unreserved inputs")


class AssetWallet:
    def open_row(self, row):
        if len(row) not in (112, 1824):
            raise ValueError("invalid AST1 note source")
        raw = self.role.call(b"D" + row)
        if raw == b"MISS":
            return None
        if len(raw) != 84 or raw[:3] != b"HIT" or raw[-1] not in (1, 2, 3):
            raise ValueError("invalid AST1 note opening")
        native, token, asset = struct.unpack_from("<QQ32s", raw, 35)
        if not valid_id(asset) or (asset == ZERO) != (token == 0) or max(native, token) > MAX_AMOUNT:
            raise ValueError("inconsistent AST1 note opening")
        return raw[3:35], native, asset, token, ("reward", "incoming", "change")[raw[-1] - 1]

    def compact_payment(self, header, request, resolved_id, to, sources):
        if len(header) != 132 or len(to) != 1601 or len(sources) not in (1, 2):
            raise ValueError("invalid AST1 payment request")
        data = bytearray(b"K" + header + request.encode(resolved_id) + to + bytes([len(sources)]))
        for row, levels in sources:
            if len(row) not in (112, 1824) or not 1 <= len(levels) <= 20:
                raise ValueError("invalid AST1 membership source")
            data.extend(struct.pack("<HB", len(row), len(levels)) + row)
            for level in levels:
                if len(level) != 3 or any(len(s) != 32 for s in level):
                    raise ValueError("invalid private membership path")
                data.extend(b"".join(level))
        raw = self.role.call(bytes(data))
        proof_size = int.from_bytes(raw[5:9], "little")
        if raw[:5] != b"AST1\x01" or not proof_size or len(raw) != 9 + proof_size + 3584:
            raise ValueError("AST1 prover refused the payment")
        return raw


class AssetState:
    def select(self, request, exclude=()):
        blocked = exclude if callable(exclude) else set(exclude).__contains__
        rows = self.db.execute("SELECT cm,amount,asset,token FROM owned "
                               "WHERE spent IS NULL AND (amount>0 OR token>0) ORDER BY pos")
        return select_amounts(rows, request, blocked)

    def pay(self, request, to, pinned):
        from wallet_sync import path_rows, role_sample
        if len(pinned) not in (1, 2) or len(set(pinned)) != len(pinned):
            raise ValueError("invalid pinned real inputs")
        self.last_payment = None
        notes, nfs, asset_ids = [], [], set()
        native_total = token_total = 0
        with self.transaction(False):
            header = self.header
            for cm in pinned:
                row = self.db.execute("SELECT origin,amount,asset,token,nf,path FROM owned "
                                      "WHERE cm=? AND spent IS NULL AND (amount>0 OR token>0)",
                                      (bytes.fromhex(cm),)).fetchone()
                if row is None or not permitted(request, row["asset"]):
                    raise ValueError("pinned input unavailable or incompatible with intent")
                if row["token"]:
                    asset_ids.add(row["asset"])
                native_total += row["amount"]
                token_total += row["token"]
                nfs.append(row["nf"])
                notes.append((row["origin"], path_rows(row["path"])))
        changes = change_for(request, native_total, token_total)
        if changes is None or len(asset_ids) > 1:
            raise ValueError("insufficient or incompatible pinned amounts")
        if request.supply:
            resolved = issuance_id(self.network, nfs[0])
        else:
            resolved = next(iter(asset_ids), ZERO)
            if request.token and resolved != request.asset:
                raise ValueError("pinned inputs do not fund selected asset")
        before = role_sample(self.wallet.role)
        packet = self.wallet.compact_payment(header, request, resolved, to, notes)
        after = role_sample(self.wallet.role)
        self.last_payment = dict(amount=request.native, asset_id=resolved.hex(), token_amount=request.token,
                                 issue_supply=request.supply, fee=FEE, input_total=native_total,
                                 token_input_total=token_total, change=changes[0], token_change=changes[1],
                                 real_inputs=len(pinned), input_commitments=list(pinned),
                                 real_nullifiers=[nf.hex() for nf in nfs],
                                 prover_cpu_s=after[0] - before[0], prover_role_peak_rss_KiB=after[1])
        self.wallet.last_payment = self.last_payment
        return packet


def tally(balance, kind, native, asset, token, sign):
    if not (native or token):
        return
    balance["balance"] += sign * native
    if token:
        key = asset.hex()
        holdings = balance["assets"]
        remaining = holdings.get(key, 0) + sign * token
        if remaining < 0:
            raise ValueError("negative private asset balance")
        if remaining:
            holdings[key] = remaining
        else:
            del holdings[key]
    balance["notes"] += sign
    balance[kind + "_notes"] += sign
    if kind != "reward":
        balance["receipt_notes"] += sign


def check_accounting(payment, intent, pins, network):
    """Check local accounting before creating reservations and the transmissible packet."""
    request = Request.from_row(intent)
    keys = ("amount", "asset_id", "token_amount", "issue_supply", "fee", "change",
            "input_total", "token_input_total", "token_change", "real_inputs",
            "prover_cpu_s", "prover_role_peak_rss_KiB")
    account = {key: payment[key] for key in keys}
    asset = bytes.fromhex(account["asset_id"])
    if (list(payment["input_commitments"]) != pins or account["real_inputs"] != len(pins)
            or (account["amount"], account["token_amount"], account["issue_supply"], account["fee"]) !=
               (request.native, request.token, request.supply, FEE)
            or not valid_id(asset)
            or (asset != ZERO) != bool(account["token_input_total"] or account["issue_supply"])
            or (request.asset != ZERO and request.asset != asset)
            or (request.supply and (account["token_input_total"] != 0 or
                                    asset != issuance_id(network, bytes.fromhex(payment["real_nullifiers"][0]))))
            or change_for(request, account["input_total"], account["token_input_total"]) !=
               (account["change"], account["token_change"])):
        raise ValueError("AST1 prover accounting differs from persisted intent")
    return account
