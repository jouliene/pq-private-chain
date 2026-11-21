import unittest

from run_genuine import (
    N7Ledger,
    derive7,
    map_asset,
    n7_activation_id,
    n7_header,
    n7_packet,
    n7_statement,
    note_bytes,
    decode_note,
    successor_backup,
    successor_domains,
)


class GenuineHarnessLightTests(unittest.TestCase):
    def test_successor_domains_are_versioned_and_deterministic(self):
        network = bytes(range(32))
        anchor = bytes(range(32, 64))
        first = successor_domains(network, 27, anchor)
        self.assertEqual(first, successor_domains(network, 27, anchor))
        self.assertNotEqual(first, successor_domains(network, 28, anchor))
        self.assertEqual(tuple(map(len, first)), (48, 48))

    def test_original_seed_derives_backup_without_becoming_public_state(self):
        seed = b"s" * 32
        network = b"n" * 32
        backup = successor_backup(seed, network, 27)
        self.assertEqual(len(backup), 48)
        self.assertEqual(backup, successor_backup(seed, network, 27))
        self.assertNotEqual(backup, successor_backup(seed, network, 28))

    def test_asset_mapping_and_note_codec_are_exact_little_endian(self):
        legacy = [0x0102030405060708, 9, 10, (1 << 63) - 1]
        mapped = map_asset(legacy)
        self.assertEqual(mapped[:2], [0x05060708, 0x01020304])
        note = {
            "owner": derive7(b"test-owner", b"owner"),
            "asset": mapped,
            "salt": derive7(b"test-salt", b"salt"),
            "native": 12,
            "token": 13,
        }
        self.assertEqual(decode_note(note_bytes(note)), note)

    def test_ordinary_n7_packet_context_and_atomic_replay(self):
        root = [1] * 7
        nfs = ([2] * 7, [3] * 7)
        outputs = ([4] * 7, [5] * 7)
        receipts = (b"a" * 1744, b"b" * 1744)
        header = n7_header(b"n" * 48, root, 2, 3, nfs, outputs, receipts)
        activation = n7_activation_id(b"c" * 32, 27, b"a" * 32, b"p" * 32)
        statement = n7_statement(activation, header)
        proof = b"proof"
        verified = []
        ledger = N7Ledger(
            root,
            2,
            activation,
            lambda public, body: verified.append((public, body)),
            ([8] * 7, [9] * 7),
            lambda _outputs: [6] * 7,
        )
        ledger.admit(n7_packet(header, proof))
        self.assertEqual(verified, [(statement, proof)])
        accepted = ledger.snapshot()
        with self.assertRaises(ValueError):
            ledger.admit(n7_packet(header, proof))
        self.assertEqual(ledger.snapshot(), accepted)
        self.assertEqual((ledger.count, ledger.fees), (4, 3))
        ledger.rollback()
        self.assertEqual((ledger.count, ledger.fees, ledger.root), (2, 0, tuple(root)))


if __name__ == "__main__":
    unittest.main()
