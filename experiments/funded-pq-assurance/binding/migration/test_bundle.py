import copy
import struct
import unittest

from bundle import BridgeBundle, HEADER, N7_RECEIPT_BYTES


def statement():
    return {
        "bridge_context": list(range(12)),
        "c_input_nullifiers": [list(range(4)), list(range(4, 8))],
        "transient_c_outputs": [list(range(8, 12)), list(range(12, 16))],
        "successor_outputs": [list(range(16, 23)), list(range(23, 30))],
    }


def bundle():
    return BridgeBundle(
        statement(),
        b"fresh-MNG3-packet",
        b"equality-proof",
        (b"a" * N7_RECEIPT_BYTES, b"b" * N7_RECEIPT_BYTES),
    )


class BundleCodecTests(unittest.TestCase):
    def test_round_trip_identity_and_exact_size(self):
        value = bundle()
        raw = value.encode()
        self.assertEqual(BridgeBundle.decode(raw), value)
        sizes = value.component_sizes()
        self.assertEqual(sizes["canonical_bundle"], len(raw))
        self.assertEqual(sizes["framing"], HEADER.size)
        self.assertEqual(sizes["successor_receipts"], 2 * N7_RECEIPT_BYTES)
        self.assertEqual(len(value.identity()), 48)

    def test_mutation_truncation_and_trailing_bytes_fail(self):
        raw = bundle().encode()
        for changed in (raw[:-1], raw + b"x", raw[:HEADER.size] + b"[" + raw[HEADER.size + 1:]):
            with self.assertRaises(ValueError):
                BridgeBundle.decode(changed)

    def test_noncanonical_statement_and_wrong_receipt_length_fail(self):
        wrong = copy.copy(bundle())
        object.__setattr__(wrong, "successor_receipts", (b"a", b"b" * N7_RECEIPT_BYTES))
        with self.assertRaisesRegex(ValueError, "N7 receipt length"):
            wrong.encode()

        raw = bundle().encode()
        _, statement_size, *rest = HEADER.unpack_from(raw)
        public = raw[HEADER.size:HEADER.size + statement_size]
        padded = public.replace(b"{", b"{ ", 1)
        header = HEADER.pack(b"C2N7B1\0\0", len(padded), *rest)
        with self.assertRaisesRegex(ValueError, "noncanonical bridge statement"):
            BridgeBundle.decode(header + padded + raw[HEADER.size + statement_size:])

    def test_length_word_corruption_fails_before_parsing(self):
        raw = bytearray(bundle().encode())
        first, = struct.unpack_from("<I", raw, 8)
        struct.pack_into("<I", raw, 8, first + 1)
        with self.assertRaisesRegex(ValueError, "framing"):
            BridgeBundle.decode(bytes(raw))


if __name__ == "__main__":
    unittest.main()
