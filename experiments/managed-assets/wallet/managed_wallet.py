"""MNG1 private payment intents and public authority calls for the ordinary wallet."""
from dataclasses import dataclass, replace
from hashlib import sha256
import struct

from asset_wallet import FEE, MAX_AMOUNT, ZERO, issuance_id, valid_id
from redemption import return_commitment, select_return


BURN = 1 << 62


@dataclass(frozen=True)
class Request:
    native: int
    asset: bytes
    token: int
    supply: int = 0
    operation: str = "transfer"
    return_tx: bytes = ZERO
    sequence: int = 0
    previous: bytes = ZERO

    def __post_init__(self):
        if not valid_id(self.asset) or any(type(n) != int or not 0 <= n <= MAX_AMOUNT
                                           for n in (self.native, self.token, self.sequence)):
            raise ValueError("invalid managed request amounts or asset")
        if (not isinstance(self.return_tx, bytes) or len(self.return_tx) != 32 or
                not isinstance(self.previous, bytes) or len(self.previous) != 32 or
                type(self.supply) != int or not 0 <= self.supply < 2 * BURN):
            raise ValueError("invalid managed return reference or delta")
        if self.operation == "transfer":
            valid = (not self.supply and (self.native or self.token) and
                     (self.asset == ZERO) == (self.token == 0))
        elif self.operation in ("register", "fixed", "mint"):
            valid = (not self.native and self.supply == self.token > 0 and
                     (self.asset != ZERO) == (self.operation == "mint"))
        elif self.operation == "burn":
            valid = (not self.native and not self.token and self.asset != ZERO and self.burn > 0
                     and self.return_tx != ZERO)
        else:
            valid = False
        if ((self.operation == "burn") != (self.return_tx != ZERO)
                or bool(self.sequence) != (self.previous != ZERO)
                or (self.operation != "mint" and self.sequence) or not valid):
            raise ValueError("inconsistent managed operation or context")

    @property
    def burn(self):
        return self.supply - BURN if self.supply >= BURN else 0

    @classmethod
    def issue(cls, supply):
        return cls(0, ZERO, supply, supply, "fixed")

    @classmethod
    def from_row(cls, row):
        return cls(row["amount"], row["asset"], row["token"], row["supply"],
                   row["operation"], row["return_tx"], row["sequence"], row["previous"])

    def encode(self, asset):
        return struct.pack("<QQ32sQ", self.native, self.token, asset, self.supply)


def default_id(address, request):
    preimage = (b"MNG1/local-intent/v1\0" + request.operation.encode() + b"\0" + address +
                request.encode(request.asset) + request.return_tx)
    return request.operation + "-" + sha256(preimage).hexdigest()[:32]


def change_for(request, native, token):
    native -= request.native + FEE
    token += (-request.burn if request.burn else request.supply) - request.token
    if 0 <= native <= MAX_AMOUNT and 0 <= token <= MAX_AMOUNT:
        return native, token
    return None


def permitted(request, asset):
    if request.operation in ("register", "mint", "fixed"):
        return asset == ZERO
    return request.asset == ZERO or asset in (ZERO, request.asset)


def bind_parent(lab, node, book, intent, request):
    """Freeze the first selected mint parent with its intent before selecting inputs or proving."""
    if request.operation != "mint":
        return request
    existing = book.db.execute("SELECT sequence,previous FROM intents WHERE id=?", (intent,)).fetchone()
    if existing is not None:
        return replace(request, sequence=existing["sequence"], previous=existing["previous"])
    # All pages are fetched from one selected tip. Ordinary sends do not use this RPC.
    from managed_inventory import inventory
    for _ in range(4):
        tip = lab.status(node)["tip"]
        try:
            entries = inventory(lab, node, tip)
        except ValueError as error:
            if str(error) != "registry tip changed":
                raise
        else:
            break
    else:
        raise ValueError("registry tip changed repeatedly during mint authorization")
    entry = entries.get(request.asset.hex())
    if entry is None or entry["mode"] != "managed":
        raise ValueError("mint requires a registered managed asset")
    if type(entry["sequence"]) != int or entry["sequence"] <= 0:
        raise ValueError("invalid managed registry sequence")
    return replace(request, sequence=entry["sequence"], previous=bytes.fromhex(entry["tx"]))


def authorize(wallet, network, request, nfs, asset_ids):
    from managed_ops import managed_id
    public = b""
    if request.operation in ("mint", "register"):
        public = wallet.role.call(b"J")
        if len(public) != 32:
            raise ValueError("invalid managed issuer public key")
    if request.operation == "register":
        asset = managed_id(network, public, nfs[0])
    elif request.operation == "fixed":
        asset = issuance_id(network, nfs[0])
    elif request.operation == "mint":
        asset = request.asset
    else:
        asset = next(iter(asset_ids), ZERO)
        if (request.token or request.burn) and asset != request.asset:
            raise ValueError("pinned inputs do not fund selected asset")
    return asset, public


def envelope(wallet, network, request, inner, public):
    from managed_ops import wrap
    def sign(digest):
        signature = wallet.role.call(b"L" + digest)
        if len(signature) != 17088:
            raise ValueError("issuer signing failed")
        return signature
    return wrap(inner, request.operation, network, public_key=public, sequence=request.sequence,
                previous=request.previous, sign=sign if public else None)


def validate_return(state, request, pins):
    expected = return_commitment(state.db, request.return_tx, request.asset, request.burn).hex()
    if pins[0] != expected:
        raise ValueError("pinned input differs from the specifically returned note")
    if len(pins) == 2:
        fee = state.db.execute("SELECT asset,token FROM owned WHERE cm=? AND spent IS NULL",
                               (bytes.fromhex(pins[1]),)).fetchone()
        if fee is None or tuple(fee) != (ZERO, 0):
            raise ValueError("redemption fee input must be native-only")


def check_accounting(payment, intent, pins, network):
    request = Request.from_row(intent)
    keys = ("amount", "asset_id", "token_amount", "issue_supply", "fee", "change", "input_total",
            "token_input_total", "token_change", "real_inputs", "prover_cpu_s", "prover_role_peak_rss_KiB")
    result = {k: payment[k] for k in keys}
    effective = bytes.fromhex(result["asset_id"])
    if (list(payment["input_commitments"]) != pins or result["real_inputs"] != len(pins)
            or (result["amount"], result["token_amount"], result["issue_supply"], result["fee"]) !=
               (request.native, request.token, request.supply, FEE)
            or not valid_id(effective)
            or (effective != ZERO) != bool(result["token_input_total"] or request.supply)
            or (request.asset != ZERO and effective != request.asset)
            or (request.supply and not request.burn and result["token_input_total"] != 0)
            or (request.burn and (result["token_input_total"] != request.burn or result["token_change"]))
            or (request.operation == "fixed" and effective != issuance_id(network, bytes.fromhex(payment["real_nullifiers"][0])))
            or change_for(request, result["input_total"], result["token_input_total"]) !=
               (result["change"], result["token_change"])):
        raise ValueError("managed prover accounting differs from the persisted intent")
    if request.operation == "register":
        from managed_ops import managed_id
        if effective != managed_id(network, bytes.fromhex(payment["issuer_key"]), bytes.fromhex(payment["real_nullifiers"][0])):
            raise ValueError("registration asset ID differs from the selected authority and funding")
    result.update(operation=request.operation, minted=request.supply if not request.burn else 0,
                  burned=request.burn)
    return result
