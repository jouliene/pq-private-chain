"""Separate measured role costs from illustrative retention and first-copy projections."""
import argparse
import json
from pathlib import Path

HERE = Path(__file__).resolve().parent


def summarize(out):
    metrics = json.loads((out/'metrics.json').read_bytes())
    replay = json.loads((out/'replayed.json').read_bytes())
    peers = json.loads((out/'peer-check.json').read_bytes())['phase_framed_observations']
    profile = json.loads((HERE.parent/'funded-upgrade/PROFILE.json').read_bytes())
    traffic = {}
    for phase, stage in metrics['home_phases'].items():
        wire = {k:sum(peer[phase][k] for peer in peers.values()) for k in ('request_B','reply_B','body_B')}
        counts = stage['progress']['archive_traffic'].values()
        assert all(wire[k] == sum(row[k] for row in counts) for k in wire)
        traffic[phase] = dict(wire, elapsed_s=stage['elapsed_s'], height=stage['height'],
                              peak_candidate_main_file_B=stage['progress'].get('scratch_peak_B',0))
    wallet = metrics['wallet']
    restored = wallet['restored']
    received = {k:restored['sync'][k] for k in ('request_B','reply_B','public_body_B','blocks','wallet_db_B')}
    received['process_elapsed_s'] = restored['process_elapsed_s']
    archive = {peer:dict(initial_download=source['sync'], initial_disk=source['disk']['logical_B'],
                         final_disk=metrics['storage'][peer]) for peer,source in metrics['archive_initial'].items()}
    # Explicit traffic scenario, one complete B operation per mined block, all edges
    # independent, no forks/issuance/transport retransmissions or future compression.
    counts = [90_000_000,10_000_000]
    ordinary, leg = profile['MNG2']['physical_frame_B'], profile['SLG2']['physical_frame_B']
    selected = [222+4+ordinary,222+2*(4+leg)]
    # Fixed common block record: height, identities, header, reward and slot count.
    block_record = 4+32+32+132+104+1
    slot_record = 32+2*32+2*(32+1792)+41
    common_records = [block_record+slot_record,block_record+2*slot_record]
    total = sum(n*b for n,b in zip(counts,selected))
    common = sum(n*b for n,b in zip(counts,common_records))
    blocks = sum(counts)
    slots = counts[0]+2*counts[1]
    duplicated_receipts_rewards = slots*2*1792 + blocks*104
    output_commitments = 32*(2*slots+blocks)
    spent_identifiers = 2*32*slots
    recent = (total*14+364)//365
    return dict(measured=dict(archives=archive,home_download=traffic, wallet_cold_scan=received,
                  wallet_incomplete_process_s=wallet['gap']['restore']['process_elapsed_s'],
                  wallet_proving={k:wallet[k]['submission']['proving_wall_s'] for k in ('initial_payment','final_payment')},
                  stopped_home=metrics['storage']['home'], stopped_wallet=metrics['storage']['wallet'],
                  archive_interpeer={k:metrics[k] for k in ('fork_seed','archive2_fork','archive1_final')},
                  final_validation=replay['home']),
                projection=dict(operations_per_year=sum(counts), B_ordinary_and_swap_counts=counts,
                  blocks_per_operation=1, block_body_B=selected, archive_body_B_per_copy_year=total,
                  two_archive_body_B_per_year=2*total, single_block_relay_edge_body_B_per_year=total,
                  recent_body_B_14_days=recent, home_common_records_B_per_year=common,
                  home_output_ciphertext_and_reward_B_per_year=duplicated_receipts_rewards,
                  home_out_cm_B_per_year=output_commitments,home_nullifier_B_per_year=spent_identifiers,
                  home_minimum_permanent_growth_B_per_year=common+duplicated_receipts_rewards+output_commitments+spent_identifiers,
                  home_first_year_minimum_B_with_14_day_window=recent+common+duplicated_receipts_rewards+output_commitments+spent_identifiers,
                  offline_wallet_full_common_record_B_per_year=common,
                  excluded='headers, frontiers, extra table columns, SQLite pages and indexes, framing, forks, temporary replay space and retries are additional'))


if __name__ == '__main__':
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('result',type=Path)
    print(json.dumps(summarize(p.parse_args().result),indent=2,sort_keys=True))
