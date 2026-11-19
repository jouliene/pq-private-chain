# Public archive custody without recursive proving

**Four of six partial archives reconstructed the original 574,984-byte DLF1 chain.** A fresh public process checked the original proofs, PoW, branch, rewards and spentness from genesis. It reached the published H10 with four payments, twelve fees, eight spent nullifiers and 1,000 units issued. Each holder stored 147,451 bytes across 20 files. The six holders together stored 884,706 bytes. This design saves space at an individual partial custodian while increasing system-wide storage. [Preregistration](REGISTER.md) · [Measured results](CUSTODY.json)

The source is a real DLF1 busy capture on the earlier network that commits the **entire** direct payment. Ten complete blocks include four 143,187-byte payments from separate wallets. Compaction did not change any block, proof, ciphertext or consensus rule. To repeat, use the DLF1 deployment and its public busy capture produced by the earlier reproduction commands. A newly generated capture has a different selected tip. No wallets, private note data, new proof generation or mining are needed for the custody command. [DLF1 reproduction](../../payment-architecture/README.md) · [Custody runner](custody.py)

```sh
python3 -IB experiments/delayed-eight/assurance/custody.py run "$lab/direct/network" "$lab/direct/busy-public"
```

The encoder splits a complete block into four equal-length slices, padding by zero to a multiple of four. Over GF(256) with polynomial 0x11d, the two parity rows are (1,1,1,1) and (1,2,4,8). Any four generator rows are invertible. In the case of two missing data rows, the remaining two coefficients in the second parity row differ, giving a nonzero two-column determinant. Each holder stores one slice and a 370-byte manifest for the block containing network, verifier profile, PoW id, parent, height, length, coding parameters, raw SHA-256 and six ordered slice hashes. This is a custom systematic maximum-distance-separable code and framing. [Finite-field FEC background, RFC 5510](https://www.rfc-editor.org/rfc/rfc5510)

The process tested all fifteen possible four-holder sets separately for each of the ten actual blocks. It then removed data shares 0 and 2 from the recovery service. A new process, given the DLF1 deployment, selected tip and addresses of four loopback servers, downloaded only their public records. It walked the parent links, reconstructed the original raw blocks, recomputed their PoW identities and replayed every state transition in order. The locator tip is agreed externally or discovered through normal chain selection. Here it came from the released public capture. The program is a bounded diagnostic for captures of up to 10,000 blocks. The native public verifier has no wallet mount.

| Actual recovery traffic | Bytes |
|---|---:|
| 50 common requests, 33 bytes each | 1,650 |
| 10 manifest bodies | 3,700 |
| 40 fragment bodies | 575,004 |
| 50 response length fields | 200 |
| **Application bytes in both directions** | **580,554** |

The client and six servers counted these application bytes independently. TCP/IP overhead, connection setup, disks' allocation units and directory metadata are excluded. The healthy run fetched just four slices for each block. A separate control encountered a connection refusal and recovered from four remaining holders. With one corrupted slice among five offered, the client rejected it and succeeded. With one corrupted slice among four, or only three offered, recovery failed. A corrupt raw digest in the first manifest was bypassed using another holder's manifest. A shard digest is meaningful relative to a manifest. An untrusted custodian cannot establish a historical block by inventing its own manifest; the receiver must check the reconstructed PoW id against its target, follow the actual parent links, and fully validate the chain.

### Annual comparison

| At 100M included payments | Sparse, TB | Busy, TB |
|---|---:|---:|
| One independently complete DLF1 archive | 14.356 | 14.326 |
| One of six partial holders | 3.650 | 3.593 |
| All six holders combined | 21.901 | 21.560 |
| Healthy cold fetch, application request and reply framing | 14.448 | 14.344 |
| Bytes written to restore one missing partial holder | 3.650 | 3.593 |
| Direct wallet uploads, before retries and relays | 14.319 | 14.319 |

The sparse mix averages 1.21 payments per paid block with one empty per paid block. The busy mix averages 3.5 with one empty per nine paid blocks. The formulas charge the legacy 222-byte block overhead, four bytes per direct attachment, padding, manifests at each holder and per-record queries. The simulation used byte strings and real sockets on one host. It does not demonstrate six independent operators, long-term retention, Sybil resistance, repairs under churn, or an availability market. Losing three custodians together can prevent future reconstruction even with valid commitments. A new independently validating node must still download the equivalent of a complete DLF1 archive and check all four wallet proofs per four payments. A custodian that also keeps the full validating archive incurs both roles. A verifier retaining hot state still needs authenticated data on a reorg, and a seed-recovering wallet still needs public receiving history. Encoded public records add availability, not witness confidentiality. The 1 TB and 5 TB figures are comparison scenarios. The 5 TB partial-holder result does not meet the independently complete-copy scenario. [Costs and arithmetic](custody.py) · [Raw run](CUSTODY.json)
