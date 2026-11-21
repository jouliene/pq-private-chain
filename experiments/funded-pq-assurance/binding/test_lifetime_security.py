import unittest
from decimal import Decimal

import lifetime_security as target


class LifetimeSecurityTests(unittest.TestCase):
    def test_scenario_counts(self):
        rows = {row["id"]: row["targets"] for row in target.scenario_targets()}
        self.assertEqual(rows["one_target_per_offered_payment_20y"], 2_000_000_000)
        self.assertEqual(rows["mixed_outputs_20y_100pct"], 4_400_000_000)
        self.assertEqual(rows["mixed_outputs_20y_95pct"], 4_180_000_000)
        self.assertEqual(rows["four_outputs_per_offer_20y"], 8_000_000_000)

    def test_minimum_limb_results(self):
        for row in target.scenario_targets():
            count = row["targets"]
            self.assertEqual(target.minimum_limbs(count, 128, "multi_target_preimage"), 5)
            self.assertEqual(target.minimum_limbs(count, 128, "arbitrary_collision"), 7)

    def test_more_targets_reduce_target_search_work(self):
        four = target.profile(4, 4_400_000_000)
        eight = target.profile(4, 8_000_000_000)
        self.assertGreater(
            Decimal(four["quantum_multi_target_preimage_query_bits"]),
            Decimal(eight["quantum_multi_target_preimage_query_bits"]),
        )

    def test_wider_profiles_increase_benchmarks(self):
        rows = [target.profile(n, 8_000_000_000) for n in (4, 5, 6, 7)]
        search = [Decimal(row["quantum_multi_target_preimage_query_bits"]) for row in rows]
        collision = [Decimal(row["quantum_arbitrary_collision_query_bits"]) for row in rows]
        self.assertEqual(search, sorted(search))
        self.assertEqual(collision, sorted(collision))

    def test_probability_envelope_and_target_memory(self):
        row = target.profile(4, 4_400_000_000)
        self.assertEqual(row["usable_target_table"]["raw_digest_bytes"], 140_800_000_000)
        multi = row["grover_probability_examples"][1]["queries"]
        self.assertEqual([trial["q"] for trial in multi], ["2^64", "2^96", "2^112", "2^128"])
        self.assertIsNotNone(multi[0]["small_angle_success_estimate"])
        self.assertIsNone(multi[-1]["small_angle_success_estimate"])
        self.assertEqual(multi[-1]["success_probability_upper_bound"], "1.000000000000E+0")

    def test_bht_memory_and_union_bound_are_explicit(self):
        row = target.profile(7, 8_000_000_000)
        self.assertGreater(row["bht_original"]["list_entries_at_least"], 2**149)
        self.assertEqual(row["bht_original"]["raw_digest_list_bytes_at_least"], row["bht_original"]["list_entries_at_least"] * 56)
        union = target.lifetime_union_bound(2_000_000_000)
        self.assertEqual(union["remaining_negative_log2_bound"], "97.102648")
        four = target.profile(4, 8_000_000_000)["cns_no_qram_collision_screen"]
        self.assertEqual(four["query_exponent_log2_soft_O"], "102.400000")
        self.assertEqual(four["classical_memory_exponent_log2_soft_O"], "51.200000")
        self.assertEqual(four["rough_linear_qubit_scale_without_hidden_constant"], 256)
        seven = row["cns_no_qram_collision_screen"]
        self.assertEqual(seven["query_exponent_log2_soft_O"], "179.200000")
        self.assertEqual(seven["classical_memory_exponent_log2_soft_O"], "89.600000")

    def test_cube_root_rounds_up(self):
        for value in (1, 2, 7, 8, 9, 26, 27, 28, target.GOLDILOCKS_ORDER**7):
            root = target.ceil_cube_root(value)
            self.assertGreaterEqual(root**3, value)
            self.assertTrue(root == 1 or (root - 1) ** 3 < value)


if __name__ == "__main__":
    unittest.main()
