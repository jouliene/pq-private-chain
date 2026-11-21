"""Compare complete packet flows and unreplicated archive sizes; decimal network units."""
import json
from pathlib import Path
from statistics import mean

ROOT = Path(__file__).resolve().parent
YEAR = 365.25 * 86400
MIX_SWAP = 0.10


def load(path):
    return json.loads(path.read_text())


def project(ordinary, swap, overhead):
    payload = (1 - MIX_SWAP) * ordinary + MIX_SWAP * swap
    framed = payload + overhead
    rows = {}
    for n in (10_000_000, 30_000_000, 100_000_000):
        inbound = n * (payload + framed)
        rows[n] = dict(archive_TB=round(n * framed / 1e12, 4),
                       wallet_inclusion_TB=round(n * payload / 1e12, 4),
                       archive_input_Mbps=round(n * framed * 8 / YEAR / 1e6, 3),
                       pre_relay_plus_block_one_copy_each_TB=round(inbound / 1e12, 4),
                       four_outgoing_peers_both_flows_Mbps=round(4 * inbound * 8 / YEAR / 1e6, 3))
    return dict(ordinary_B=ordinary, swap_B=swap, block_extra_B=overhead,
                weighted_framed_B=round(framed, 2), per_included_operations=rows)


def main():
    actual = load(ROOT / 'RESULT.json')
    sha = load(ROOT / 'sha3/PRICE.json')
    blocks = actual['final']['verification']
    ordinary = mean(b['packet_B'] for b in blocks[:2])
    for b in blocks:
        assert b['block_B'] == b['packet_B'] + 180
    v = [m for b in blocks for m in b['legs']]
    probe = lambda k: [round(min(m[k] for m in v), 3), round(max(m[k] for m in v), 3)]
    cpu = mean(m['user_s'] + m['system_s'] for m in v)
    # Historical product envelopes are exact. Compare their payload separately from the isolated block.
    live = project(143233, 320905, 0)
    expected_body = 232113.5867
    report = dict(
        N7_measured_sample_projection=project(ordinary, blocks[2]['packet_B'], 180),
        N7_IID_query_mean_projection=project(3841+expected_body, 12+2*(21014+expected_body), 180),
        N7_shape_max=project(3841+246120, 12+2*(21014+246120), 180),
        N3_priced=project(sha['ordinary_bytes'], sha['swap_bundle_bytes'], 180),
        live_payload_only=live,
        verification=dict(fresh_per_leg_CPU_mean=round(cpu, 4), prep_ms_range=probe('preparation_ms'),
                          check_ms_range=probe('operation_ms'), projected_proof_cores_at_100M=round(110_000_000*cpu/YEAR, 2)),
        N7_max_frame=dict(old=262144, isolated=272*1024, max_signed=267134,
                          increment_per_64_full_queued_frames_B=64*16*1024,
                          increment_ser_time_20Mbps_ms=round(16*1024*8/20e6*1000, 3)),
        recovery=dict(legs_per_year=110_000_000, envelope_attempts_20yr=4_400_000_000,
                      N7_scan_projection_B_per_leg=1+4*56+2*1744,
                      N7_scan_projection_TB_20yr=20*110_000_000*(1+4*56+2*1744)/1e12,
                      N7_nf_plus_leaf_and_parent_GB_year=3*56*220_000_000/1e9))
    print(json.dumps(report, indent=2))


if __name__ == '__main__':
    main()
