"""Install a real wallet driver plus instrumentation of the private local HTTP fixture."""
from pathlib import Path
import subprocess
import sys

here = Path(__file__).resolve().parent
q = Path(sys.argv[1]).resolve()
assert subprocess.check_output(["git", "-C", q, "rev-parse", "HEAD"], text=True).strip() == "f04c91307837c0231668383bec76ba98d89d2652"
def replace_once(s, old, new):
    assert s.count(old) == 1, old
    return s.replace(old, new)

# Preserve upstream support/mod.rs; place the instrumented test fixture in a
# different module to avoid changing any stock wallet or server code on disk.
tests = q / "crates/qnero-wallet/tests"
src = (tests / "support/mod.rs").read_text()
src = replace_once(src, "pub struct NodeState {", """pub struct NodeState {
    pub http: Vec<[usize; 4]>,
    pub publish_on_submit: Vec<(Vec<u8>, Vec<u8>)>,""")
src = replace_once(src, "    let mut length = 0usize;", """    let mut length = 0usize;
    let mut request_line = 0usize;
    let mut headers = 0usize;""")
src = replace_once(src, '        if line == "\\r\\n" || line == "\\n" {',
                  '''        if request_line == 0 { request_line = line.len(); } else { headers += line.len(); }
        if line == "\\r\\n" || line == "\\n" {''')
src = replace_once(src, "        state.requests.push(body.clone());", """        state.requests.push(body.clone());
        state.http.push([request_line, headers, length, 0]);""")
src = replace_once(src, "    write!(\n        stream,\n        \"HTTP/1.1 200 OK", "    let reply = format!(\n        \"HTTP/1.1 200 OK")
src = replace_once(src, "        encoded\n    )?;\n    stream.flush()", """        encoded
    );
    state.lock().unwrap().http.last_mut().unwrap()[3] = reply.len();
    stream.write_all(reply.as_bytes())?;
    stream.flush()""")
src = replace_once(src, "                state.head_number = next;", """                state.head_number = next;
                for (key, value) in std::mem::take(&mut state.publish_on_submit) {
                    state.put_storage(&key, &value);
                }""")
module = tests / "meter_support/mod.rs"
module.parent.mkdir(exist_ok=True)
module.write_text(src)
wallet = (here.parent / "comparative_wallet.rs").read_text()
wallet = replace_once(wallet, "mod support;", '#[path="meter_support/mod.rs"]\nmod support;\nuse codec::{Compact, Decode, Encode};')
wallet = replace_once(wallet, "let funding = sender.miner_key().coinbase_note(&state.genesis_hash(), 1, 1000)?;",
                      """let genesis = state.genesis_hash();
    let funding = sender.miner_key().coinbase_note(&genesis, 1, 54)?;
    let second = sender.miner_key().coinbase_note(&genesis, 2, 59)?;""")
wallet = replace_once(wallet, "append_leaf(&mut state, 0, 1, funding.commitment(), Some(1000));",
                      """append_leaf(&mut state, 0, 1, funding.commitment(), Some(54));
    append_leaf(&mut state, 1, 2, second.commitment(), Some(59));""")
wallet = replace_once(wallet, "sender.store.unspent_total() == 1000", "sender.store.unspent_total() == 113")
wallet = replace_once(wallet, "let prepare_s = start.elapsed().as_secs_f64();",
                      "let prepare_s = start.elapsed().as_secs_f64();\n    ensure!(payment.input_leaves.len() == 2 && payment.change == 5);")
wallet = replace_once(wallet, '"funded_commitments_at_anchor": 1', '"funded_commitments_at_anchor": 2, "real_inputs":2')
begin = wallet.index("    json!(", wallet.index("fn traffic"))
end = wallet.index("\n}",begin)
wallet = wallet[:begin] + '''    let rows = &state.http[from..];
    assert_eq!(rows.len(), requests.len());
    let total = |i: usize| rows.iter().map(|r| r[i]).sum::<usize>();
    let json_bytes: usize = requests.iter().map(String::len).sum();
    assert_eq!(total(2), json_bytes);
    json!({"requests":rows.len(),"http_request_line_bytes":total(0),"http_request_header_bytes":total(1),
        "json_request_body_bytes":json_bytes,"http_outgoing_bytes":total(0)+total(1)+json_bytes,
        "http_incoming_bytes":total(3)})''' + wallet[end:]
# Capture the ext body/headers of each functional phase. Arm fixture state only
# at the actual author_submitExtrinsic request (equivalent publication changes
# are validated independently in the FRAME test). No witness reaches the server.
a = wallet.index("    // Exact request emitted")
b = wallet.index("    let mut recipient = recipient;", a)
wallet = wallet[:a] + '''    let mut cms = Vec::new();
    for raw in &ciphertexts {
        let ct = NoteCiphertext::from_bytes(raw)?;
        let recv = decrypt_note(&recipient.ivk(), &ct).ok();
        let change = decrypt_note(&sender.ivk(), &ct).ok();
        ensure!(recv.is_some() != change.is_some());
        cms.push(recv.or(change).unwrap().commitment);
    }
    fs::write(public.join("commitments.bin"), cms.iter().flat_map(|cm| cm.to_bytes()).collect::<Vec<_>>())?;
    {
        let mut state = node.state();
        state.include_submissions = true;
        // Build a list of public key/value updates without applying them until
        // the RPC server sees the normal wallet submission.
        for (i, cm) in cms.iter().enumerate() {
            state.publish_on_submit.push((identity_map_key("ZkTree","Leaves",2+i as u64), cm.to_bytes().to_vec()));
            state.publish_on_submit.push((identity_map_key("Shielded","LeafBlocks",2+i as u64), 3u32.to_le_bytes().to_vec()));
        }
        state.publish_on_submit.push((identity_map_key("ZkTree","Leaves",4), Digest::hash_bytes(&[b"ordinary fixture coinbase"]).to_bytes().to_vec()));
        state.publish_on_submit.push((identity_map_key("Shielded","LeafBlocks",4), 3u32.to_le_bytes().to_vec()));
        state.publish_on_submit.push((identity_map_key("Shielded","CoinbaseValues",4), 1u64.to_le_bytes().to_vec()));
        state.publish_on_submit.push((storage_prefix("ZkTree","LeafCount"),5u64.to_le_bytes().to_vec()));
        state.publish_on_submit.push((storage_prefix("ZkTree","Depth"),vec![2]));
        for nf in payment.nullifiers {
            state.publish_on_submit.push((qnero_wallet::scale::blake2_128_concat_map_key("Shielded","UsedNullifiers",&nf), Vec::new()));
        }
    }
    let before_submit = node.state().requests.len();
    let report = sender.submit_spend(&chain, &metadata, payment.clone())?;
    ensure!(report.included_at == 3);
    let submit = traffic(&node,before_submit);
    let initial_submission = {
        let state = node.state();
        let rows = state.requests[before_submit..].iter().enumerate()
            .filter(|(_,s)| s.contains("author_submitExtrinsic")).collect::<Vec<_>>();
        ensure!(rows.len()==1);
        let index = before_submit + rows[0].0;
        let req: Value = serde_json::from_str(&state.requests[index])?;
        ensure!(req["params"][0] == hex_0x(&extrinsic));
        state.http[index]
    };
''' + wallet[b:]
wallet = replace_once(wallet, "let anchor = chain.block_hash(payment.anchor_block)?;",
                      "let anchor = node.state().hash_at(payment.anchor_block);")
marker = "    let result = json!({"
wallet = replace_once(wallet, marker, '''    // Forensic header readback is excluded from the wallet role phases.
    let functional_traffic = traffic(&node,0);
    let hash = node.state().hash_at(report.included_at);
    let raw = chain.header_at(&hash)?;
    ensure!(raw.to_header_inputs()?.block_hash().to_bytes() == hash);
    let mut header = hex::decode(raw.parent_hash.trim_start_matches("0x"))?;
    header.extend(raw.block_number()?.encode()); // qp_header::Header.number is plain u32, not Compact<u32>.
    for value in [&raw.state_root,&raw.extrinsics_root,&raw.zk_tree_root] {
        header.extend(hex::decode(value.trim_start_matches("0x"))?);
    }
    header.extend(Compact(raw.digest.logs.len() as u32).encode());
    for log in &raw.digest.logs { header.extend(hex::decode(log.trim_start_matches("0x"))?); }
    // OpaqueExtrinsic's SCALE Vec<u8> wraps the entire payload. Re-encoding
    // its decoded bytes once adds only Vec<Extrinsic>'s one-item prefix.
    let mut input = &extrinsic[..];
    let opaque = Vec::<u8>::decode(&mut input)?;
    ensure!(input.is_empty() && opaque.encode() == extrinsic);
    let notification = vec![opaque].encode();
    ensure!(notification[0] == 4 && notification[1..] == extrinsic);
    let ex_root = qnero_state_proof::extrinsics_root(&[extrinsic.clone()]).map_err(anyhow::Error::msg)?;
    ensure!(hex_0x(&ex_root) == raw.extrinsics_root);
    let mut block = header.clone();
    block.extend(&notification);
    fs::write(public.join("fixture-block.scale"), &block)?;
    fs::write(public.join("transaction-notification.scale"), &notification)?;
    let result = json!({
        "functional_traffic_all_roles":functional_traffic,
        "one_submission_http_request_line_headers_body_response":initial_submission,
        "fixture_block_header_bytes":header.len(),"fixture_block_bytes":block.len(),
        "extrinsic_vec_and_notification_bytes":notification.len(),
        "successful_sender_confirmed_at":report.included_at,''')
(tests / "metered_send.rs").write_text(wallet)
