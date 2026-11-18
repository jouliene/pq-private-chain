// Integration test overlay for the pinned qnero-wallet crate.
mod support;

use anyhow::{ensure, Result};
use qnero_aggregator::artifacts::serialize_verifier_data;
use qnero_notes::{decrypt_note, Digest, NoteCiphertext};
use qnero_prover::WalletProver;
use qnero_wallet::chain::Chain;
use qnero_wallet::extrinsic::{encode_submit_private_batch, extrinsic_payloads};
use qnero_wallet::keys::create_seed;
use qnero_wallet::rpc::{hex_0x, RpcClient};
use qnero_wallet::scale::{identity_map_key, storage_prefix};
use qnero_wallet::wallet::{HighFee, MerkleSource, Wallet, NUM_LEAF_PROOFS};
use serde_json::{json, Value};
use std::{env, fs, path::Path, time::Instant};
use support::{FakeNode, NodeState};

fn append_leaf(state: &mut NodeState, index: u64, block: u32, cm: Digest, coinbase: Option<u64>) {
    state.put_storage(&identity_map_key("ZkTree", "Leaves", index), &cm.to_bytes());
    state.put_storage(&identity_map_key("Shielded", "LeafBlocks", index), &block.to_le_bytes());
    if let Some(value) = coinbase {
        state.put_storage(&identity_map_key("Shielded", "CoinbaseValues", index), &value.to_le_bytes());
    }
    state.put_storage(&storage_prefix("ZkTree", "LeafCount"), &(index + 1).to_le_bytes());
}

fn traffic(node: &FakeNode, from: usize) -> Value {
    let state = node.state();
    let requests = &state.requests[from..];
    json!({"json_rpc_request_bodies": requests.len(), "json_rpc_request_bytes":
        requests.iter().map(String::len).sum::<usize>()})
}

fn cpu_ticks() -> Result<u64> {
    let stat = fs::read_to_string("/proc/self/stat")?;
    let fields = stat.rsplit_once(')').ok_or_else(|| anyhow::anyhow!("invalid proc stat"))?.1
        .split_ascii_whitespace().collect::<Vec<_>>();
    Ok(fields[11].parse::<u64>()? + fields[12].parse::<u64>()?)
}

fn create_wallet(path: &Path) -> Result<Wallet> {
    create_seed(path)?;
    Wallet::open(path)
}

#[test]
fn ordinary_wallet_payment() -> Result<()> {
    let private = env::var("QNERO_PRIVATE")?;
    let private = Path::new(&private);
    let public = env::var("QNERO_PUBLIC")?;
    let public = Path::new(&public);
    let mut sender = create_wallet(&private.join("sender.seed"))?;
    let recipient_path = private.join("recipient.seed");
    let recipient = create_wallet(&recipient_path)?;
    let backup = private.join("backup.seed");
    fs::copy(&recipient_path, &backup)?;

    // A laboratory coinbase funds one authenticated commitment. No private key
    // or opening is given to the RPC fixture. The recipient sees no payment yet.
    let metadata = support::test_metadata();
    let mut state = NodeState { head_number: 2, ..Default::default() };
    state.put_storage(&storage_prefix("ZkTree", "Depth"), &[1]);
    let funding = sender.miner_key().coinbase_note(&state.genesis_hash(), 1, 1000)?;
    append_leaf(&mut state, 0, 1, funding.commitment(), Some(1000));
    let node = FakeNode::start(state);
    let rpc = RpcClient::new(&node.url);
    let chain = Chain::new(&rpc);
    sender.sync(&chain, &metadata)?;
    ensure!(sender.store.unspent_total() == 1000, "funded wallet synchronization failed");
    let funding_sync = traffic(&node, 0);

    ensure!(NUM_LEAF_PROOFS == 6, "unexpected wallet batch profile");
    let setup_cpu = cpu_ticks()?;
    let start = Instant::now();
    let prover = WalletProver::new(NUM_LEAF_PROOFS)?;
    prover.ensure_supported_verifiers()?;
    let setup_s = start.elapsed().as_secs_f64();
    let setup_ticks = cpu_ticks()? - setup_cpu;
    let start_count = node.state().requests.len();
    let start = Instant::now();
    let prepare_cpu = cpu_ticks()?;
    let payment = sender.prepare_spend(&chain, &metadata, &prover, &recipient.address(), 100, None, "",
                                       MerkleSource::Local, HighFee::Refuse)?;
    let prepare_s = start.elapsed().as_secs_f64();
    let prepare_ticks = cpu_ticks()? - prepare_cpu;
    let prepare_reads = traffic(&node, start_count);
    let verifier = serialize_verifier_data(&prover.batch_verifier_data(), "private batch")?;
    fs::write(public.join("private-verifier.bin"), verifier)?;
    let extrinsic = encode_submit_private_batch(&metadata, &payment.proof, &payment.outputs)?;
    let ciphertexts = extrinsic_payloads(&metadata, &extrinsic)?;
    ensure!(ciphertexts.len() == 2);
    let anchor = chain.block_hash(payment.anchor_block)?;
    fs::write(public.join("anchor.bin"), anchor)?;
    fs::write(public.join("wallet-proof.bin"), &payment.proof)?;
    fs::write(public.join("payment.scale"), &extrinsic)?;

    // Exact request emitted by the real RPC client. The server captures the
    // body but is deliberately not a mining or settlement engine.
    let before_submit = node.state().requests.len();
    chain.submit_extrinsic(&extrinsic)?;
    let submit = traffic(&node, before_submit);
    {
        let state = node.state();
        let req: Value = serde_json::from_str(&state.requests[before_submit])?;
        ensure!(req["method"] == "author_submitExtrinsic");
        ensure!(req["params"][0] == hex_0x(&extrinsic));
    }

    // Build the small public history used by recipient scanning from actual
    // ordered ciphertexts. The verifier separately checks these commitments.
    let mut commitment_bytes = Vec::new();
    {
        let mut state = node.state();
        state.head_number = 3;
        state.blocks.insert(3, vec![hex_0x(&extrinsic)]);
        for (index, raw) in ciphertexts.iter().enumerate() {
            let ct = NoteCiphertext::from_bytes(raw)?;
            let recv = decrypt_note(&recipient.ivk(), &ct).ok();
            let change = decrypt_note(&sender.ivk(), &ct).ok();
            ensure!(recv.is_some() != change.is_some());
            let item = recv.or(change).unwrap();
            append_leaf(&mut state, (index + 1) as u64, 3, item.commitment, None);
            commitment_bytes.extend_from_slice(&item.commitment.to_bytes());
        }
        append_leaf(&mut state, 3, 3, Digest::hash_bytes(&[b"laboratory coinbase"]), Some(1));
    }
    fs::write(public.join("commitments.bin"), commitment_bytes)?;
    let mut recipient = recipient;
    let before = node.state().requests.len();
    let receipt = recipient.sync(&chain, &metadata)?;
    ensure!(receipt.received == 1 && recipient.store.unspent_total() == 100);
    let receive_traffic = traffic(&node, before);
    drop(recipient);
    let mut recovered = Wallet::open(&backup)?;
    ensure!(recovered.store.notes.is_empty());
    let before = node.state().requests.len();
    let restore = recovered.sync(&chain, &metadata)?;
    ensure!(restore.received == 1 && recovered.store.unspent_total() == 100);
    let recovery_traffic = traffic(&node, before);

    let result = json!({
        "wallet_slots": NUM_LEAF_PROOFS, "real_leaves": 1, "funded_commitments_at_anchor": 1,
        "fee_steps": payment.fee, "ciphertext_lengths": ciphertexts.iter().map(Vec::len).collect::<Vec<_>>(),
        "proof_bytes": payment.proof.len(), "extrinsic_bytes": extrinsic.len(), "anchor_height": payment.anchor_block,
        "funding_sync": funding_sync, "prepare_reads": prepare_reads, "submit": submit,
        "receive_from_public_history": receive_traffic, "seed_only_recovery": recovery_traffic,
        "setup_cpu_ticks": setup_ticks, "prepare_cpu_ticks": prepare_ticks,
        "wallet_setup_elapsed_s": setup_s, "prepare_spend_elapsed_s": prepare_s,
        "leaf_and_private_batch_prove_elapsed_s": payment.proving.as_secs_f64(),
        "independent_recipient_received": true, "backup_only_received": true
    });
    fs::write(public.join("wallet.json"), serde_json::to_vec_pretty(&result)?)?;
    Ok(())
}
