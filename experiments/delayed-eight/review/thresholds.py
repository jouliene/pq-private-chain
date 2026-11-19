"""Independent decimal archive and work accounting for a public eight-payment certificate."""
from __future__ import annotations

import argparse
from fractions import Fraction as F
import json
from math import ceil

YEAR = 365 * 24 * 3600
PAYMENTS = 100_000_000
OFFER = 143_187
RECEIPTS = 3_584
SID = 32
CORE = 222 + 4
CERT_HEADER = 9 + 4
MIX = {'sparse': (100, 85, 10, 4, 1), 'busy': (100, 45, 90, 135, 630)}


def as_number(x):
    return round(float(x), 9)


def evaluate(proof=None, cpu=None, wall=None):
    offer_rate = F(PAYMENTS, YEAR)
    package_rate = offer_rate / 8
    mixtures = {}
    for name, counts in MIX.items():
        placements = sum(w * n for w, n in enumerate(counts))
        blocks_per_payment = F(sum(counts), placements)
        core_share = CORE * blocks_per_payment + SID
        cases = {}
        for useful in (2, 4, 6, 8):
            fixed = 8 * RECEIPTS + CERT_HEADER + useful * core_share
            active_only = useful * RECEIPTS + CERT_HEADER + useful * core_share
            row = dict(full_eight_with_orphaned_slots_proof_B_1_5TB=[int(limit * useful - fixed) for limit in (10000, 50000)],
                       underfilled_all_active_slots_useful_proof_B_1_5TB=[int(limit * useful - active_only) for limit in (10000, 50000)])
            if proof is not None:
                row['archive_TB_with_all_8_receipt_pairs'] = as_number(F(PAYMENTS, 10**12) * (fixed + proof) / useful)
                row['archive_TB_with_only_active_receipt_pairs'] = as_number(F(PAYMENTS, 10**12) * (active_only + proof) / useful)
            cases[str(useful)] = row
        mixtures[name] = dict(blocks_per_payment=str(blocks_per_payment),
                              paid_mean_occupied_slots=str(F(placements, sum(counts[1:]))),
                              useful_slots_only=cases,
                              no_builder_direct_initial_archive_TB=as_number((core_share + 4 + OFFER) * PAYMENTS / 10**12))
        if proof is not None:
            # Interpolate between complete full certificates and directly retained singletons.
            compact = core_share + F(CERT_HEADER + proof + 8 * RECEIPTS, 8)
            directly_retained = core_share + OFFER + 4
            if compact < directly_retained:
                mixtures[name]['maximum_direct_fraction_1_5TB'] = [
                    None if limit < compact else as_number(min(1, (limit - compact) / (directly_retained - compact)))
                    for limit in (10000, 50000)]
    service = dict(offers_per_s=as_number(offer_rate), full_certificates_per_s=as_number(package_rate),
                   interval_s_for_full_group=as_number(1 / package_rate),
                   one_day_uncertified_original_packet_B=as_number(offer_rate * 86400 * OFFER),
                   total_sender_payload_TB=as_number(F(PAYMENTS * OFFER, 10**12)))
    if cpu is not None:
        service['builder_CPU_cores_at_average_rate'] = as_number(package_rate * cpu)
    if wall is not None:
        service['minimum_serial_builder_copies_at_average_rate'] = ceil(package_rate * wall)
    return dict(included_per_year=PAYMENTS, year_s=YEAR, proof_B=proof, mixes=mixtures, service=service)


if __name__ == '__main__':
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--proof-B', type=int)
    p.add_argument('--cpu-s', type=F)
    p.add_argument('--wall-s', type=F)
    args = p.parse_args()
    if any(v is not None and v <= 0 for v in (args.proof_B, args.cpu_s, args.wall_s)):
        p.error('all supplied costs must be positive')
    print(json.dumps(evaluate(args.proof_B, args.cpu_s, args.wall_s), sort_keys=True, indent=2))
