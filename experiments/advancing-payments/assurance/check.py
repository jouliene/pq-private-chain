"""Independent decoder for the APV2 fork's locally registered public verifier bytes."""
import argparse
import hashlib
import json
from pathlib import Path

HERE = Path(__file__).resolve().parent
P = 2**64 - 2**32 + 1
LAYERS = {"leaf":26, "wallet":26, "outer2":54, "outer3":80, "outer4":106}


class Reader:
    def __init__(self, data):
        self.data = data
        self.i = 0

    def n(self, size=8):
        end = self.i+size
        if end > len(self.data):
            raise ValueError("truncated verifier parameters")
        v = int.from_bytes(self.data[self.i:end], "little")
        self.i = end
        return v


def require(value, why):
    if not value:
        raise ValueError(why)


def fri(r):
    rate, cap, queries, grind = r.n(), r.n(), r.n(), r.n(4)
    require(r.n(1) == 1, "expected ConstantArityBits")
    return (rate, cap, queries, grind, r.n(), r.n())


def parse(data):
    r = Reader(data)
    cap_height = r.n()
    require(cap_height == 4, "unexpected verifier-only cap")
    for _ in range((2**cap_height+1)*4):
        require(r.n() < P, "noncanonical verifier digest limb")
    only = data[:r.i]
    common = data[r.i:]
    parameters = [r.n() for _ in range(6)]
    arithmetic, zk = r.n(1), r.n(1)
    f = fri(r)
    trace_degree = r.n()
    require(fri(r) == f, "derived FRI parameters disagree")
    count = r.n()
    require(count < 32, "unreasonable reduction count")
    reduction = [r.n() for _ in range(count)]
    degree, hiding, public_degree = r.n(), r.n(1), r.n()
    # Selectors precede the quotient and public input dimensions.
    for lanes in (1, 2):
        n = r.n()
        require(n <= (len(data)-r.i)//(8*lanes), "bad selector dimensions")
        r.i += 8*n*lanes
    quotient, gate_constraints, constants, pi = [r.n() for _ in range(4)]
    require(0 < pi <= 1024 and 0 < quotient <= parameters[5], "bad PLONK dimensions")
    bits = degree
    derived = []
    while bits > 5 and bits+f[0]-4 >= f[1]:
        derived.append(4)
        bits -= 4
    require(derived == reduction, "unexpected derived reduction arities")
    return dict(wires=parameters[0],routed=parameters[1],constants_config=parameters[2],target=parameters[3],
                challenges=parameters[4],max_quotient=parameters[5],base_arithmetic=arithmetic,
                zk=zk,fri=list(f),trace_degree_bits=trace_degree,degree_bits=degree,public_degree_bits=public_degree,
                reduction_arity_bits=reduction,leaf_hiding=hiding,public_inputs=pi,
                quotient_degree_factor=quotient,gate_constraints=gate_constraints,common_constants=constants), only, common


def inspect(layer, raw, stock=False):
    c, only, common = parse(raw)
    leaf = layer == "leaf"
    for k, v in dict(wires=143 if leaf else 135,routed=80 if leaf else 60,constants_config=2,
                     target=100 if stock else 128,challenges=2,max_quotient=8,base_arithmetic=1,
                     zk=int(not leaf),leaf_hiding=int(not leaf),fri=[3,4,28 if stock else 43,16 if stock else 0,4,5]).items():
        require(c[k] == v, f"{layer}: {k} mismatch")
    if not stock:
        require(c["public_inputs"] == LAYERS[layer], f"{layer}: public-input arity")
    return c, only, common


def hash_record(raw):
    return dict(bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest(),
                blake2b512=hashlib.blake2b(raw).hexdigest())


def unique_keys(pairs):
    obj = {}
    for key, value in pairs:
        require(key not in obj, f"duplicate manifest key: {key}")
        obj[key] = value
    return obj


def check(dirpath, expected):
    manifest = (dirpath/"profile.json").read_bytes()
    require(hashlib.sha256(manifest).hexdigest() == expected, "unapproved manifest")
    declared = json.loads(manifest, object_pairs_hook=unique_keys)
    for key, value in dict(suite="APV2",security_bits=128,extension_degree=2,challenges=2,
                           query_rounds=43,rate_bits=3,cap_height=4,grinding_bits=0).items():
        require(declared.get(key) == value, f"manifest field: {key}")
    names = [row["name"] for row in declared["layers"]]
    require(names == list(LAYERS), "manifest layer order or count")
    out = dict(manifest=hash_record(manifest), layers={})
    for arity, layer in enumerate(LAYERS):
        row = declared["layers"][arity]
        raw = (dirpath/f"{layer}.vk").read_bytes()
        c, only, common = inspect(layer, raw)
        require(only == (dirpath/f"{layer}.only").read_bytes(), f"{layer}: verifier-only")
        require(common == (dirpath/f"{layer}.common").read_bytes(), f"{layer}: common")
        hashes = {name:hash_record(data) for name,data in (("vk",raw),("common",common),("only",only))}
        for part, identity in hashes.items():
            require(identity["blake2b512"] == row[f"{part}_blake2b512"], f"{layer}: {part} differs from approved manifest")
        for key, value in dict(arity=arity,degree_bits=c["trace_degree_bits"],public_inputs=c["public_inputs"],
                               wires=c["wires"],routed=c["routed"],hiding=bool(c["zk"])).items():
            require(row.get(key) == value, f"{layer}: manifest {key} disagrees with bytes")
        out["layers"][layer] = dict(parsed=c, artifacts=hashes)
    return out, declared


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--registry", type=Path)
    p.add_argument("--approve-manifest", help="independently approved SHA-256 of profile.json")
    p.add_argument("--stock", type=Path, help="inspect the historical stock private-wallet artifact")
    args = p.parse_args()
    if args.stock:
        c, _, _ = inspect("wallet", args.stock.read_bytes(), stock=True)
        try:
            inspect("wallet", args.stock.read_bytes())
        except ValueError as e:
            reason = str(e)
        else:
            raise ValueError("stock profile accepted as APV2")
        print(json.dumps(dict(stock=c, rejected_as_APV2=reason), sort_keys=True, indent=2))
    else:
        require(args.registry and args.approve_manifest, "required registry and external manifest approval")
        out, _ = check(args.registry, args.approve_manifest)
        print(json.dumps(out, sort_keys=True, indent=2))


if __name__ == "__main__":
    main()
