"""Run local acceptance negatives against both actual swap proofs and both genuine spend-key roles."""
import argparse
from pathlib import Path
import sys


def rejected(fun, *args):
    try:
        fun(*args)
    except ValueError:
        return
    raise AssertionError("incorrect receipt or proposal accepted")


def main():
    p = argparse.ArgumentParser(description=__doc__)
    for name in ("home","terms","leg_a","leg_b"):
        p.add_argument(name,type=Path)
    p.add_argument("wallet_a")
    p.add_argument("wallet_b")
    args = p.parse_args()
    home = args.home.resolve()
    sys.path.insert(0,str(home/"deployment/devnet"))
    from cli import Lab
    from swap_wallet import MAX_LEG, actor, check_pair, opened, read_file, term_file, verify, wallet_address
    lab = Lab(home,home/"deployment/runtime")
    terms = term_file(args.terms)
    files = [read_file(path,MAX_LEG) for path in (args.leg_a,args.leg_b)]
    with actor("verify") as public:
        effects = [verify(public,raw) for raw in files]
        check_pair(effects)
        for i,raw in enumerate(files):
            modified = bytearray(raw)
            modified[-1] ^= 1
            rejected(verify,public,bytes(modified))
            # Substitute the other leg's real encrypted outputs while preserving this proof.
            rejected(verify,public,raw[:-3584]+files[1-i][-3584:])
    for i,name in enumerate((args.wallet_a,args.wallet_b)):
        own, other = terms.parties[i], terms.parties[1-i]
        with lab.locked_wallet(name) as private, lab.wallet(name) as owner, actor("wallet",private) as wallet:
            wallet_address(wallet,owner)
            terms.confirm(i,owner.address,own.give,own.qty,other.give,other.qty)
            rejected(terms.confirm,i,other.address,own.give,own.qty,other.give,other.qty)
            opened(wallet,effects[1-i],0,0,other.give,other.qty)
            rejected(opened,wallet,effects[1-i],0,0,other.give,other.qty-1)
            rejected(opened,wallet,effects[1-i],0,0,own.give,other.qty)
            rejected(opened,wallet,effects[1-i],0,1,other.give,other.qty)
            rejected(opened,wallet,effects[i],0,0,own.give,own.qty)
            rejected(opened,wallet,effects[1-i],1,0,other.give,other.qty)
    print("PASS: both genuine legs, both spend-key-owned incoming openings; changed ciphertexts, transplanted "
          "receipts, wrong owner, wrong role, wrong asset, wrong native or token amounts and counterparty change refused")


if __name__ == "__main__":
    main()
