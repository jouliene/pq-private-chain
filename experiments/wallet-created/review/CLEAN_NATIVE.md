# Independent recursive-pair and pallet review

## Separate native wallet, builder and node

The clean detached project revision was `4ab7e6fa4699b94821c7978c37d98fe9c600ea08`. I used a second, initially clean upstream checkout of `DigitalGuards/qnero@f04c91307837c0231668383bec76ba98d89d2652`, the earlier Cargo dependency cache, the pinned Rust 1.93.0 toolchain and the unchanged lockfile. I built the frozen example with the supported native build command, checked the resulting executable digest independently, and confirmed the scratch overlay was removed. Both source checkouts were clean afterwards. Each role ran in its own filesystem/process/network namespace.

Both new wallets generated independent keys and locally owned two funded notes at the trusted four-leaf genesis. Each sent a 147,324 B one-slot submission to the builder. The builder returned a 157,220 B packet. Both owners opened two notes apiece. One then generated a new payment from its recovered pair of notes. The independent public node admitted the pair and the successor. The resulting state had height three, ten funded commitments, six spent nullifiers and nine fee units. Changed proof, changed public fee, changed ciphertext, short encoding, trailing byte and replay each failed; the calculated state identity and counters stayed intact after each failure. [Clean measurements](CLEAN_NATIVE.json)

The fresh genesis digest was `51d84759f9de341beb07606d39a9aa90e9a491b67c2b7b78c555a40721f1ba75`. I then ran two separate node-only replays using exactly three retained artifacts each: genesis, paired packet and successor packet. One used this reviewer history and one used the author history at genesis `3ae5613ac227880476a57eb912cba7e033588655b38e90d9f6d77e2e046713ff`. Both passed the two genuine public verifications and all six rejection checks. No inner wallet packet, private note, proof witness, wallet or builder process was available to these node replays. The [independent wire decoder](native_wire.py) also compared the original two public submissions with the retained proof for both histories. The wrapper forwarded all 52 input field elements in order and retained all four ciphertexts byte-for-byte. The outer packet contained 150,044 proof bytes, 7,168 ciphertext bytes and eight framing bytes.

On the clean run, wallet creation took 4.63 / 4.52 s elapsed (9.03 / 8.79 CPU s). The independent builder took 8.61 s elapsed / 16.73 CPU s after setup. The pair-accept step on the node's tiny in-memory state used about 7 ms CPU after setup. Each comparison uses ordinary native-asset payments, source-derived circuit identities and a fixed accepted tip. The observed 137,428 B of archival saving for the two bodies leaves a 78,610 B committed share per settled payment and the full 147,324 B origin packet per offered payment. Neither the two independent private authorizations nor recording their pair makes a bilateral atomic swap. The separate token-fee and joint swap sketches require new circuits and admission rules.

## Stock FRAME settlement

I checked the native pallet checkout against the same upstream Qnero pin, compared both Cargo lockfiles and each test-only overlay to the recorded SHA-256 manifest, and verified the tracked pallet addition was exactly one `cfg(test)` module declaration. I reused the already built FRAME test ELF, SHA-256 `2dfa4153e3b38f186f959fbbceb2fb4e0c5fb5cf1d3b107ee023c9b65f0de741`; I did not rebuild the separate FRAME dependency tree. My [public replay](frame_public.py) gave it empty stdin, a fresh process/network namespace, and precisely the seven selected public payment/funding/header artifacts. The ledger ran the pinned pool, pre-dispatch and dispatch paths. After the synthetic 1,000-step endowment it held 992 steps, with four burned, four pending author compensation, two spent nullifiers and three funded leaves. The actual final tree root matched the recorded result, both output memberships passed, and replay failed all three paths. This concerns a selected laboratory anchor and FRAME TestExternalities. It supplies no network consensus, mining or live-availability evidence. [Checked source and public results](CLEAN_FRAME.json)

## Reproduction

Use an empty output directory and clean checkout for each native build. The approved public genesis comes from the independent selected history. The wallet generation call writes only shareable public packets and aggregate counters to the output directory.

```sh
d=experiments/wallet-created
python3 -IB "$d/native/build.py" "$qnero_checkout" "$cargo_target" "$native"
python3 -IB "$d/native/run.py" "$native" "$native_sha" "$new_cycle"
python3 -I "$d/review/native_wire.py" "$new_cycle/a.body" "$new_cycle/b.body" "$new_cycle/pair.block"
python3 -IB "$d/native/run.py" "$native" "$native_sha" "$public_only_dir" --replay "$public_genesis_sha"
python3 -I "$d/review/frame_public.py" "$pallet_source_checkout" "$d/qnero" "$pallet_result/source.json" "$pallet_result/public" "$pallet_result/summary.json" "$frame_test" "$frame_test_sha"
```

## Stock two-funded-input HTTP follow-up

A further independent test verified the captured public default wallet proof from the separate two-funded-input HTTP run using my clean build's verifier and release-pinned artifact. The changed-proof and changed-ciphertext controls passed. I parsed its SCALE submission and checked the encoded one-element notification was exactly `0x04` followed by the 154,508 B payment. The fixture block had its own 171 B header followed by that 154,509 B vector, totaling 154,680 B. Its public verifier and byte-accounting checks were run independently. The source wallet reported both selected inputs inside the wallet; the hidden input count does not follow from the public proof. The metered test covered 62 HTTP requests. I checked the five stages' recorded totals sum to 330,436 B sent and 988,606 B received. The actual submission request contained 17 B request line, 119 B headers and 309,091 B JSON body, then received a 194 B HTTP response. These totals concern a loopback client, its selected synthetic RPC server and a fresh funded fixture. There was no separate independent replay of the HTTP instrumentation or live P2P broadcast. [Checked public artifacts and totals](CLEAN_HTTP.json)
