"""Public replay and cross-process framing controls for the signed funding fixture."""
import hashlib
import json
from pathlib import Path
import subprocess
import sys
from tempfile import TemporaryDirectory
import unittest

FIXTURE = Path(__file__).with_name("funding_fixture.py")


class SignedPrefixTest(unittest.TestCase):
    def test_authoritative_prefix(self):
        with TemporaryDirectory() as tmp:
            directory = Path(tmp)/"prefix"

            def call(mode, *args, reject=False):
                proc = subprocess.run([sys.executable, "-IB", FIXTURE, mode, directory, *args],
                                      stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                      stderr=subprocess.PIPE)
                # Only compare status. Never print a private stdout or include it in an exception.
                self.assertEqual(proc.returncode == 0, not reject)
                if reject:
                    self.assertFalse(bool(proc.stdout))
                return proc.stdout

            private = json.loads(call("new"))
            self.assertEqual(sorted(p.name for p in directory.iterdir()),
                             ["genesis.bin", "issue0.bin", "issue1.bin"])
            genesis = (directory/"genesis.bin").read_bytes()
            pin = hashlib.sha256(genesis).hexdigest()
            a = call("ledger", pin)
            b = call("ledger", pin, "reverse")
            self.assertEqual(a[:4], b"HMF1")
            self.assertEqual(int.from_bytes(a[68:72], "little"), 13)
            self.assertEqual(len(a), 72+13*128)
            self.assertEqual(a[:-256], b[:-256])
            self.assertEqual(a[-256:-128]+a[-128:], b[-128:]+b[-256:-128])
            self.assertNotEqual(a[-256:-128], a[-128:])
            self.assertEqual(len(private), 2)
            self.assertEqual(sorted(0 < int.from_bytes(bytes.fromhex(v["qty"]), "little")
                                    for v in private), [False, True])
            for v in private:
                index = v["index"]
                self.assertTrue(0 <= index < 13)
                pos = 72+128*index
                self.assertTrue(bytes.fromhex(v["occ"]+v["cm"]) == a[pos:pos+128])

            call("ledger", "0"*64, reject=True)
            first = directory/"issue0.bin"
            original = first.read_bytes()
            for changed in (original[:-1]+bytes([original[-1]^1]),
                            original[:132] + bytes([original[132]^1]) + original[133:],
                            original+b"\0", original[:-1], (directory/"issue1.bin").read_bytes()):
                first.write_bytes(changed)
                call("ledger", pin, reject=True)
            first.write_bytes(original)
            # Digests of malformed founding records cannot legalize invalid grants or cardinality.
            for offset in (132, 136+64):
                invalid = genesis[:offset]+bytes([0])+genesis[offset+1:]
                (directory/"genesis.bin").write_bytes(invalid)
                call("ledger", hashlib.sha256(invalid).hexdigest(), reject=True)


if __name__ == "__main__":
    unittest.main()
