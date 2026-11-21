# Independent public reproduction

I cloned the public HTTPS origin into an empty directory with Git credentials, prompts, system/global configuration, alternates and local object-directory overrides disabled. Both the clone's origin/main and the detached tested revision were `0ec22fafdaab0f168ac6de1e7348215bdc5e2612`. I checked ancestry from the previous public handoff `4a9a315da451c47ddddd9c235b451a194e67c436`. Running the published reproduction command with a fresh Cargo home, upstream checkout, build targets and wallet home exited successfully. The source checkout remained clean. The author archive checksum passed and its reconstructed public result matched the committed PUBLIC.json byte for byte. The fresh run used the identical original genesis and distinct funding blocks, asset IDs, authority and wallets. [Tested revision](https://github.com/jouliene/pq-private-chain/commit/0ec22fafdaab0f168ac6de1e7348215bdc5e2612) · [One-command reproduction](../README.md) · [Independent measurements](FRESH.json)

| Selected state in the new run | Native subsidy | Cumulative fees | Spent identities | Funded occurrences |
|---|---:|---:|---:|---:|
| A-funded H12 | 1,200 | 18 | 12 | 24 |
| H13 on either competing branch | 1,300 | 21 | 14 | 27 |
| B payments and signed swap, H18 | 1,800 | 30 | 22 | 40 |
| A alternative selected, H19 | 1,900 | 21 | 14 | 33 |
| B history restored, H20 | 2,000 | 30 | 22 | 42 |

All 27 retained graph blocks passed the independent reader. It rebuilt funded roots, rewards, branch eligibility, supply revisions, miner fees and current spentness. Seven MNG1, three MNG2 and two SLG2 public proofs were verified on this graph. OpenSSL independently accepted the issuer signature and both swap approvals. The H13 conflicting proposals shared a real funded identity and the two histories diverged at the same H12 tip. The H18 swap exchanged seven fixed for nine managed units, paid three native on its first leg, and used two 200,068-byte physical frames. The independent numerical reconstruction matched each participant balance reported at the recorded stages, including rollback and restoration. Final supply was 80 fixed, 100 managed and 2,000 native. Miners received 2,030 gross credits. A new wallet-free peer started at original genesis and reached the same H20 tip in 7.54 seconds. [Public reader](public.py) · [Disclosed amount reconciliation](fixture_amounts.py)

In an additional branch test, a B proof funded at H11 was refused for H12 and the same bytes were accepted in a mined H13. A valid A ordinary payment at H15 was accepted by the historical rules and refused under the upgrade. A genuine A managed registration remained eligible at H15. An already-indexed historical store containing the retired payment was refused when opened under upgraded software. Clean reconstruction from the public archive also reproduced the author's corresponding boundary checks. [Height-boundary reader](../boundary.py)

With the owner's original 32-byte backup as the only private input, two fresh native roles, one for A and one for B, independently opened the selected public receipts preceding each spend. Each role found the same single positive note for the offline owner, with 20 native and 12 managed units, and derived its real nullifier. That nullifier occurs in the admitted B payment. The forward recipient's read-only wallet index identified its incoming 12 native and eight managed as the only real input to its subsequent B payment. Repeating the backup-only comparison for the conflict owner linked the sole 20-native note to both H13 proposals. These ownership links used participant access. The public history separately establishes proof validity, branch-local spentness and accounting. [Private-role check with aggregate output](recovery.py)

The matched ordinary spend took 5.07 seconds and 451,808 KiB of prover peak RSS under A, and 9.86 seconds and 886,900 KiB under B. Warm complete public crypto calls took median 0.00654/0.00912 native core-seconds per ordinary A/B payment and 0.02309/0.02722 per complete signed A/B pair. The old pair came from the checksummed historic release. The warm samples exclude the initial key reconstruction and full PoW admission. Each new ordinary submission measured 182,855 bytes, and each B swap bundle measured 400,149 bytes. The experiment establishes funded compatibility under the tested schedule. Whole-system quantum knowledge, joint receipt privacy and protection against earlier invalid A funds remain open. [Design review](DESIGN.md)

I packaged the independent graph's 27 public blocks, one additional boundary block and the signed swap in a 2,525,342-byte release asset. I downloaded that asset from the public release and compared it byte for byte with the locally allowlisted package. To recheck it after the main reproduction, set `result` to that command's result directory and run the following from the repository root. [Independent archive](https://github.com/jouliene/pq-private-chain/releases/download/funded-upgrade-2026-11-21/funded-upgrade-independent.tar.gz)

```sh
mkdir "$result/independent"
curl -fLsS --proto '=https' --proto-redir '=https' \
  https://github.com/jouliene/pq-private-chain/releases/download/funded-upgrade-2026-11-21/funded-upgrade-independent.tar.gz \
  -o "$result/independent/graph.tar.gz"
(cd "$result/independent" && echo '6a5f8e762ed7ffeb7717f30d7bf55327984194ebfb9ebb62cf0270c6b5cbde09  graph.tar.gz' | sha256sum -c -)
tar -xzf "$result/independent/graph.tar.gz" -C "$result/independent"
python3 -IB experiments/funded-upgrade/review/public.py "$result/independent/public" \
  "$result/network/deployment" "$result/helpers" "$result/node-v24.22.1-linux-x64/bin/node"
python3 -IB experiments/funded-upgrade/boundary.py "$result/network/deployment-a" \
  "$result/network/deployment" "$result/independent/public"
```
