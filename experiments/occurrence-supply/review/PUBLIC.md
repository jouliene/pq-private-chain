# Independent reproduction of occurrence-indexed supply

The published command passed at commit `e2f4647dbe5200122c4d41bfab84de3d746d8b9f`. I cloned the public repository by HTTPS into an empty directory with Git credentials, system/global configuration and local transport disabled. The clone used no alternate object store. Public main advertised the tested revision, and the Phase 1C handoff was its ancestor. The run used a new private case directory, the default four checksummed downloads and the pinned upstream commit. The source checker regenerated 12 source hashes, matched the registered MNG3 key and native verifier, and passed five reward vectors. [Source correspondence](../ASSUMPTIONS.md)

```sh
bash experiments/occurrence-supply/reproduce.sh "$(mktemp -d)/case"
```

## Recovery and selected state

A fresh wallet restored only its 32-byte backup and synchronized public history from genesis. It recovered one note holding 19 tokens and 9 native units. The confirmed onward payment delivered 7 tokens and 4 native units, returned 12 tokens and 2 native units in change, and paid the fee of 3. The spend had one real input and two public marks. I independently read the restored wallet and all three selected ledgers and confirmed the unique eligible occurrence, the two public marks and the durable change. At H48 the nodes agreed on 104 output leaves, 56 spent marks and 78 cumulative fees. The three disclosed token balances summed to the fixed supply of 40. The authorized wallet summary matched the published observation byte for byte. [Published aggregate](../observed.json)

| Public summary | Reproduced SHA-256 |
|---|---|
| `wallet-result.json` | `91ab378d8cfd40609a0d197b82a277178eae9acc59900f6fb27a44bde54878fa` |
| `kernel-result.json` | `64be3fc60db9c9a670aa0bf70569cb3046216a0f1d9bac65cf9b292ab48492b1` |
| `source-result.json` | `1579e589721d64eaa7a348f8aafd854dd2c4bd9c054eb1238a6940684ad9259c` |

## What the proof establishes

Lean 4.19.0 checked 51 named results with warnings as errors. Their printed dependencies used only `propext`, `Classical.choice` and `Quot.sound`. For the restored spend, the executable Lean check reconstructed the eligible header and selected tree root and checked the private path. In the general proof, a real spend selects an occupied member of the eligible prefix. Branch-wide commitment uniqueness gives it one position. Binding of the body and owner-key preimages makes every compatible spend opening of that position yield the same real nullifier. A prior debit would therefore contradict public freshness. The argument derives the unused position without assigning all newly created outputs future spend identifiers. [Occurrence proof](../Occurrence.lean) · [Eligible membership](../Member.lean)

My independent finite control exhibits a positive occurrence for which no compatible spending opening exists. Adding a dummy mark creates no occurrence debit and preserves all seven units. Its toy functions illustrate the model's assumptions. Agreement with the older nullifier-filtered accounting follows under the stronger hypotheses that all births have compatible, distinct labels, the trace accounts for the real and dummy marks, and dummy marks are separate from those labels. [Independent control](Boundary.lean) · [Phase 1B agreement](../Agreement.lean)

The history induction covers modeled ordinary, supply and reward steps from a faithful prefix. Applying it to the deployed chain still requires witness existence for the exact accepted statement, applicable header/tree/body/key binding, and a faithful interpretation of earlier real spends and births. A public replay checks inherited consensus records. Reconstructing their complete private debit history requires the earlier witnesses. The conserved quantity is committed face value. Recovery and spendability were observed for the participating wallet. [Source and assumption audit](../ASSUMPTIONS.md)
