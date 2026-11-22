"""Exhaust the selected base field, check the inverse map and trace linearization coordinates."""
import os
from pathlib import Path
import sys

os.environ["SW_FIELD"] = "gf256"
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
import numpy as np
import sw_wide
from backend import pack_coeff, pack_secret
from field import random_fields, mul, xor
from subfield import ALPHA, BETA, EMBED, F, fmul, join, split


def main():
    all_f = np.arange(65536).astype(F)
    assert len(set(EMBED)) == 65536
    # For all field elements, multiplication by the generator commutes with the embedding.
    assert np.array_equal(EMBED[fmul(all_f,2)], mul(EMBED,ALPHA))
    for a in (1<<j for j in range(16)):
        assert np.array_equal(EMBED[all_f^a], EMBED[all_f]^EMBED[a])
    for i in range(256):
        unit = 1<<i
        assert join(split(unit)) == unit
        coord = np.zeros(16,F)
        coord[i//16] = 1<<(i%16)
        assert np.array_equal(split(join(coord)),coord)
    for j in range(16):
        # A fault confined to any single extension coordinate affects the public linear form.
        masks = np.array([BETA[j]],dtype=object)
        x = pack_secret(np.array([1,0,1]),masks)
        wcoef = np.array([19,7,83,sw_wide.mul(2,ALPHA)],dtype=object)
        c = pack_coeff(wcoef,3)
        true = wcoef[0]^wcoef[2]^sw_wide.mul(wcoef[-1],masks[0])
        assert xor(mul(c,EMBED[x])) == true
        x[3+j] = 0
        assert xor(mul(c,EMBED[x])) != true
    private = np.array([1,0,1],dtype=object)
    masks = random_fields((56,))
    coefs = random_fields((len(private)+len(masks),))
    assert xor(mul(pack_coeff(coefs,len(private)),EMBED[pack_secret(private,masks)])) == xor(
        mul(coefs,np.concatenate([private,masks])))
    print("65536 base-field elements, 256 basis vectors and all 16 trace component positions passed")


if __name__ == "__main__":
    main()
