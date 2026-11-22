"""Call the fixed native verifier with a genesis pin, canonical statement and public proof."""
import ctypes
from functools import lru_cache
import os
from pathlib import Path


@lru_cache(maxsize=1)
def _entry(path):
    lib = ctypes.CDLL(path)
    fn = lib.sgm1_verify
    ptr, size = ctypes.c_char_p, ctypes.c_size_t
    fn.argtypes = [ptr,size,ptr,size,ptr,size,ctypes.POINTER(ctypes.c_char),size]
    fn.restype = ctypes.c_int
    return fn


def verify(pin: bytes, statement: bytes, proof: bytes):
    if not all(isinstance(v,bytes) for v in (pin,statement,proof)):
        raise ValueError("expected byte strings")
    path = os.environ.get("SGM1_NATIVE_LIB", str(Path(__file__).with_name("libsgm1_verify.so")))
    err = ctypes.create_string_buffer(256)
    if _entry(path)(pin,len(pin),statement,len(statement),proof,len(proof),err,len(err))!=1:
        raise ValueError("SGM1 proof rejected: "+err.value.decode("utf-8","replace"))
    return True
