# Independent-node payment validation

Read [the decision](DECISION.md) for the integration outcome and the exact scope of each result. The baseline is `7c2d0fc8b68c566d13e3e341c1f49bacaad527f4`. The CP03 payment, ledger and wallet source remain unchanged.

| Reproduction | Inputs and scope |
|---|---|
| [Masked outer reduction](primary/README.md) | Python 3.11+, no packages. Generate and check small genuine EF5 proofs and controls. Reprice all components of a complete ordinary payment from its actual circuit dimensions. |
| [Registered relation and public verifier kernel](dimensions/README.md) | Use a checked CP03 installation built with BUILD.md. Reproduce matrix counts, negative relation control, full-size CPU measurements and two full-length RS row checks. |
| [Independent parameter and Merkle arithmetic](review/ASSESSMENT.md) | Standard Python. Check the expected/worst-case sizes, memory, and opening work in the public reference payments. |
| [Transparent accelerator](aggregate/README.md) | Fetch the pinned upstream source. Build the normal CPU backend, prove the CP03 leaf kernel, verify in a separate process, repeat wrong-input and corrupted-proof controls, and price 96 public payments. |
| [Role model](roles/README.md) | Pure Python, actual CP03 public receipts and the public matrix measurement. Run the 95%/100% role calculations and the independent accounting checks. |

The [non-author reproduction](review/CLEAN_REPRODUCTION.md) records the tested revisions, reused dependencies, fresh proofs, public verifier checks and independent disposition. [Independent results](review/CLEAN_RESULTS.json).

The role-model command below selects the independently reviewed central sizing case. The compact block receipt size is a sensitivity, measured data and assumed inputs are distinguished in the output.

```sh
python3 -I -B experiments/node-validation/roles/project.py --masked-body-bytes 262850 --masked-max-body-bytes 272556 --aggregate-proof-bytes 200000
python3 -I -B experiments/node-validation/roles/check.py
python3 -I -B experiments/node-validation/review/schedule_check.py | diff -u experiments/node-validation/review/schedule-check.json -
python3 -I -B experiments/node-validation/review/merkle_work.py
```
