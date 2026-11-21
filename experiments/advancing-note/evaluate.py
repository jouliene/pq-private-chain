"""Price the exact 9-transfer/1-swap sample at the stated owner workload."""
import argparse
import json
from pathlib import Path
from statistics import mean, median

YEAR = 365.25*86400
ANNUAL = 100_000_000
OPS_S = ANNUAL/YEAR


def span(data, key):
    v=[d[key] for d in data]
    return [round(min(v),5),round(max(v),5)]


def result(r):
    samples=r['public']['trials']
    rows=samples[0]['warm']
    assert len(samples)==3 and len(rows)==10
    key_ids={m['registered_vk_sha3_384'] for s in samples for b in s['warm'] for m in b['legs']}
    assert len(key_ids)==1
    packet=sum(b['packet_B'] for b in rows)
    archive=sum(b['block_B'] for b in rows)
    assert archive==packet+1800
    traffic=[]
    for n in (10_000_000,30_000_000,ANNUAL):
        # The scenario includes exactly the offered load. Full payments and block bodies are counted separately.
        out=lambda amount,peers: round(peers*amount*n/10*8/YEAR/1e6,3)
        traffic.append(dict(included_per_year=n,public_wallet_upload_TB=round(n*packet/10/1e12,5),
            canonical_archive_TB=round(n*archive/10/1e12,5),one_block_ingress_Mbps=out(archive,1),
            four_peers_preinclusion_and_block_Mbps=out(packet+archive,4),
            four_peers_full_body_once_Mbps=out(archive,4),two_peers_full_body_once_Mbps=out(archive,2)))
    warm=[b for s in samples for b in s['warm']]
    legs=[m for b in warm for m in b['legs']]
    full_batch_cpu=[sum(b['full_cpu_s'] for b in s['warm']) for s in samples]
    batch_cpu=median(full_batch_cpu)
    boundary=[s['cpu_s'] for s in samples]
    # Cold CPU for Python+native, warm server CPU (includes already reaped signature children, disk commits).
    cpu_bound=median(boundary)/10*OPS_S
    affected=[r['wallets'][k] for k in ('first-two-real','unrelated','restored-onward','carol-leg','dana-leg')]
    cold=[s['cold'] for s in samples]
    throughput=10/median(s['wall_s'] for s in samples)
    return dict(registered_vk_sha3_384=key_ids.pop(),frame=dict(reference=262144,isolated_cap=272*1024,
           honest_body_max=246120,ordinary_max=249961,signed_max=267134,pair_max=534280,
           actual_transfer_B=[b['packet_B'] for b in rows[:-1]],signed_actual_B=r['exchange']['signed_leg_B'],
           swap_actual_B=rows[-1]['packet_B'],weighted_block_B=archive/10),
       cold_node=dict(wall_s=span(cold,'wall_s'),cpu_s=span(cold,'cpu_s'),peak_tree_RSS_KiB=span(cold,'sampled_tree_RSS_KiB')),
       funded_wallet=dict(ordinary_or_leg_wall_s=span(affected,'wall_s'),peak_tree_RSS_KiB=span(affected,'sampled_tree_RSS_KiB'),
          restore_only=r['wallets']['restore-one-note'],restored_send=r['wallets']['restored-onward']),
       warm_node=dict(physical_cpus=r['public']['cpu_affinity'],unique_operations=10,replays=len(samples),
          full_admission_CPU_s_by_batch=[round(x,6) for x in full_batch_cpu],
          full_admission_core_s_per_mixed_operation=round(batch_cpu/10,6),
          unique_ingress_cores_at_100M=round(batch_cpu/10*OPS_S,4),
          twice_verified_cores_at_100M=round(batch_cpu/10*OPS_S*2,4),
          request_boundary_CPU_s=boundary,request_boundary_cores_at_100M=round(cpu_bound,4),
          serial_ops_per_s_at_request_boundary=round(throughput,3),
          ordinary_wall_s=span([b for b in warm if len(b['legs'])==1],'elapsed_s'),
          swap_wall_s=span([b for b in warm if len(b['legs'])==2],'elapsed_s'),
          warm_tree_RSS_KiB=span(samples,'sampled_tree_RSS_KiB'),native_check_ms=span(legs,'operation_ms')),
       transfers_per_second_at_100M=round(OPS_S,5),cold_vs_warm_note='End-to-end replay includes signature and state workers.',
       flows=traffic,anchor_design=dict(old_window=8,new_window=64,mean_arrival_interval_s=round(1/OPS_S,6),
          eight_states_seconds_at_mean=round(8/OPS_S,4),sixty_four_states_seconds_at_mean=round(64/OPS_S,4),
          additional_raw_anchor_B=56*(56+8),retained_undo_blocks=8),
       storage=dict(keys_per_year=440_000_000,index_raw_key_GB_per_year=24.64,
          observed_index_after_ten_operations=samples[0]['index_stat'],
          home_2TB_archive_only_days=round(2e12/(archive/10*ANNUAL)*365.25,3),
          cold_full_history_TB_after_20_years=round(archive/10*ANNUAL*20/1e12,3),
          priced_14day_body_retention_TB=round(archive/10*ANNUAL*14/365.25/1e12,4),
          retained_private_scan_payload_TB_year_if_authenticated=round(3713*110_000_000/1e12,6)))

if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('result',type=Path)
    a=p.parse_args()
    print(json.dumps(result(json.loads(a.result.read_bytes())),indent=2))
