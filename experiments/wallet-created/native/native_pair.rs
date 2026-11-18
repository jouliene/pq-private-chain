//! Wallet-owned blinding followed by native recursion over two public submissions.
use anyhow::{anyhow, ensure, Context, Result};
use blake2::{Blake2b512, Digest as BlakeDigest};
use plonky2::field::types::{Field, PrimeField64};
use plonky2::iop::witness::{PartialWitness, WitnessWrite};
use plonky2::plonk::circuit_builder::CircuitBuilder;
use plonky2::plonk::circuit_data::{CircuitData, VerifierCircuitData};
use plonky2::plonk::proof::ProofWithPublicInputsTarget;
use qnero_aggregator::artifacts::{
    canonical_leaf_verifier_data, canonical_private_batch_verifier_data, serialize_verifier_data,
};
use qnero_aggregator::recursive::add_recursive_verifiers;
use qnero_aggregator::{Proof, C, D, F};
use qnero_circuit::chain::{ct_digest, SUITE_1_CIPHERTEXT_BYTES};
use qnero_circuit::config::qnero_private_batch_circuit_config;
use qnero_circuit::header::{HeaderInputs, DIGEST_LOGS_SIZE};
use qnero_circuit::merkle::CommitmentTree;
use qnero_circuit::witness::{InputNote, OutputNote, SpendWitness};
use qnero_notes::{
    encrypt_note, pad_memo, try_receive, Address, Digest, Note, NoteCiphertext, SpendingKey,
};
use qnero_prover::WalletProver;
use rand::{Rng, RngCore};
use std::collections::HashSet;
use std::io::{self, Read, Write};

const LIMIT: usize = 1_048_576;
const CT: usize = SUITE_1_CIPHERTEXT_BYTES;
const TAG: u64 = 0x4e4154503031;
const CHAIN: &[u8] = b"pq-private-chain/research/native-pair/1";
const SINGLE: &[u8; 4] = b"NPC1";
const PAIR: &[u8; 4] = b"NPA1";

type Verifier = VerifierCircuitData<F, C, D>;
type Targets = Vec<ProofWithPublicInputsTarget<D>>;
type Word = [u8; 32];

// Linux process CPU time includes all prover threads. Peak RSS is cumulative for this role.
#[repr(C)]
struct Timespec {
    seconds: i64,
    nanos: i64,
}
extern "C" {
    fn clock_gettime(id: i32, t: *mut Timespec) -> i32;
}
fn process_cpu() -> f64 {
    let mut time = Timespec {
        seconds: 0,
        nanos: 0,
    };
    // CLOCK_PROCESS_CPUTIME_ID, Linux x86-64 POSIX clock ABI.
    assert_eq!(unsafe { clock_gettime(2, &mut time) }, 0);
    time.seconds as f64 + time.nanos as f64 * 1e-9
}
struct Meter {
    start: std::time::Instant,
    cpu: f64,
}
impl Meter {
    fn start() -> Self {
        Self {
            start: std::time::Instant::now(),
            cpu: process_cpu(),
        }
    }
    fn finish(self, name: &str) {
        let cpu = process_cpu() - self.cpu;
        let seconds = self.start.elapsed().as_secs_f64();
        let status = std::fs::read_to_string("/proc/self/status").unwrap();
        let rss = status
            .lines()
            .find(|l| l.starts_with("VmHWM:"))
            .unwrap()
            .split_whitespace()
            .nth(1)
            .unwrap();
        eprintln!("METER {name} {seconds:.9} {cpu:.9} {rss}");
    }
}
fn read_frame(r: &mut impl Read) -> Result<Vec<u8>> {
    let mut len = [0; 4];
    r.read_exact(&mut len)?;
    let n = u32::from_le_bytes(len) as usize;
    ensure!(n <= LIMIT, "frame limit");
    let mut bytes = vec![0; n];
    r.read_exact(&mut bytes)?;
    Ok(bytes)
}
fn write_frame(w: &mut impl Write, bytes: &[u8]) -> Result<()> {
    ensure!(bytes.len() <= LIMIT, "frame limit");
    w.write_all(&(bytes.len() as u32).to_le_bytes())?;
    w.write_all(bytes)?;
    w.flush()?;
    Ok(())
}
fn fixed_words(raw: &[u8]) -> Result<Vec<Digest>> {
    ensure!(
        !raw.is_empty() && raw.len() % 32 == 0 && raw.len() <= 32 * 16,
        "fixture leaf list"
    );
    raw.chunks_exact(32)
        .map(|v| Ok(Digest::from_slice(v)?))
        .collect()
}
fn header(
    leaves: &[Digest],
    height: u32,
    parent: Digest,
) -> Result<(HeaderInputs, CommitmentTree)> {
    let tree = CommitmentTree::new(leaves, CommitmentTree::depth_for(leaves.len())?)?;
    // The selected fixture header commits to the full ordered list as well as the sorted tree.
    let mut ordered = Vec::from(CHAIN);
    ordered.extend_from_slice(&(leaves.len() as u64).to_le_bytes());
    for leaf in leaves {
        ordered.extend_from_slice(&leaf.to_bytes());
    }
    let h = HeaderInputs::new(
        parent,
        height,
        Digest::hash_bytes(&[&ordered]).to_bytes(),
        Digest::hash_bytes(&[CHAIN, b"fixture-header"]).to_bytes(),
        tree.root(),
        &[0; DIGEST_LOGS_SIZE],
    )?;
    Ok((h, tree))
}
fn genesis_parent() -> Digest {
    Digest::hash_bytes(&[CHAIN, b"genesis"])
}

fn verifier() -> Result<Verifier> {
    canonical_private_batch_verifier_data(&canonical_leaf_verifier_data(), 1)
}
fn wrapper(inner: &Verifier) -> Result<(CircuitData<F, C, D>, Targets)> {
    let config = qnero_private_batch_circuit_config();
    ensure!(
        config.zero_knowledge && inner.common.config.zero_knowledge,
        "blinding profile"
    );
    let mut builder = CircuitBuilder::<F, D>::new(config);
    let targets = add_recursive_verifiers(&mut builder, &inner.common, &inner.verifier_only, 2)?;
    let tag = builder.constant(F::from_canonical_u64(TAG));
    builder.register_public_input(tag);
    for t in &targets {
        ensure!(t.public_inputs.len() == 26, "one inner slot");
        builder.register_public_inputs(&t.public_inputs);
    }
    for i in 0..5 {
        builder.connect(targets[0].public_inputs[i], targets[1].public_inputs[i]);
    }
    Ok((builder.build::<C>(), targets))
}

struct Packet<'a> {
    proof: &'a [u8],
    ciphertexts: &'a [u8],
    pair: bool,
}
fn packet(raw: &[u8]) -> Result<Packet<'_>> {
    ensure!(raw.len() >= 8 && raw.len() <= LIMIT, "packet length");
    let pair = &raw[..4] == PAIR;
    ensure!(pair || &raw[..4] == SINGLE, "packet version");
    let len = u32::from_le_bytes(raw[4..8].try_into()?) as usize;
    let ct_len = if pair { 4 * CT } else { 2 * CT };
    ensure!(
        len > 0 && len <= LIMIT - 8 - ct_len && raw.len() == 8 + len + ct_len,
        "packet framing"
    );
    Ok(Packet {
        proof: &raw[8..8 + len],
        ciphertexts: &raw[8 + len..],
        pair,
    })
}
fn encode(pair: bool, proof: &Proof, cts: &[u8]) -> Vec<u8> {
    let data = proof.to_bytes();
    let mut out = Vec::from(if pair { PAIR } else { SINGLE });
    out.extend_from_slice(&(data.len() as u32).to_le_bytes());
    out.extend_from_slice(&data);
    out.extend_from_slice(cts);
    out
}
fn parse_proof(bytes: &[u8], v: &Verifier) -> Result<Proof> {
    let proof =
        Proof::from_bytes(bytes.to_vec(), &v.common).map_err(|_| anyhow!("proof decode"))?;
    ensure!(proof.to_bytes() == bytes, "canonical proof");
    v.verify(proof.clone())
        .map_err(|_| anyhow!("cryptographic verification"))?;
    Ok(proof)
}
fn word(f: &[F]) -> Word {
    let mut bytes = [0; 32];
    for (i, v) in f.iter().enumerate() {
        bytes[8 * i..8 * i + 8].copy_from_slice(&v.to_canonical_u64().to_le_bytes());
    }
    bytes
}
#[derive(Default)]
struct Effects {
    spent: HashSet<Word>,
    added: Vec<Digest>,
    fees: u64,
}
fn effects(p: &Packet, proof: &Proof, anchor: Digest, height: u32) -> Result<Effects> {
    let pi = &proof.public_inputs;
    let slots = if p.pair {
        ensure!(
            pi.len() == 53 && pi[0].to_canonical_u64() == TAG,
            "outer version"
        );
        &pi[1..]
    } else {
        ensure!(pi.len() == 26, "inner version");
        &pi[..]
    };
    let mut effects = Effects::default();
    let mut outputs = HashSet::new();
    for (s, ct) in slots
        .chunks_exact(26)
        .zip(p.ciphertexts.chunks_exact(2 * CT))
    {
        ensure!(
            word(&s[..4]) == anchor.to_bytes() && s[4].to_canonical_u64() == height as u64,
            "anchor"
        );
        for off in [5, 9] {
            ensure!(
                effects.spent.insert(word(&s[off..off + 4])),
                "repeated nullifier"
            );
        }
        for off in [13, 17] {
            let w = word(&s[off..off + 4]);
            ensure!(
                w != [0; 32] && outputs.insert(w),
                "padding/duplicate commitment"
            );
            effects.added.push(Digest::from_bytes(&w)?);
        }
        let fee = s[21].to_canonical_u64();
        ensure!((1..1 << 62).contains(&fee), "fee");
        effects.fees = effects.fees.checked_add(fee).context("fee overflow")?;
        ensure!(
            ct_digest(&[&ct[..CT], &ct[CT..]]) == word(&s[22..26]),
            "receipt binding"
        );
        for raw in ct.chunks_exact(CT) {
            let cipher =
                NoteCiphertext::from_bytes(raw).map_err(|_| anyhow!("ciphertext encoding"))?;
            ensure!(
                qnero_circuit::chain::declared_crypto_suite(raw) == Some(1)
                    && cipher.to_bytes() == raw,
                "ciphertext suite/encoding"
            );
        }
    }
    Ok(effects)
}

struct Wallet {
    key: SpendingKey,
    notes: Vec<Note>,
    prover: WalletProver,
}
impl Wallet {
    fn pay(&self, leaves: &[Digest], height: u32, parent: Digest, to: &Address) -> Result<Vec<u8>> {
        ensure!(self.notes.len() == 2, "two locally owned notes");
        let (h, tree) = header(leaves, height, parent)?;
        let keys = self.key.derived();
        let input = |n: &Note| -> Result<InputNote> {
            let idx = leaves
                .iter()
                .position(|x| *x == n.commitment())
                .context("absent funding")?;
            InputNote::real(&keys, n, tree.path(idx)?)
        };
        let mut rng = rand::rng();
        let total = self.notes[0]
            .value
            .checked_add(self.notes[1].value)
            .context("value")?;
        let amount = total / 2;
        let fee = 3;
        let change = total.checked_sub(amount + fee).context("balance")?;
        let own = self.key.address();
        let mut dest = [(to, amount), (&own, change)];
        if rng.random::<bool>() {
            dest.swap(0, 1);
        }
        let mut random = || {
            let mut w = [0; 32];
            rng.fill_bytes(&mut w);
            w
        };
        let mut w = SpendWitness {
            header: h,
            depth: tree.depth(),
            inputs: [input(&self.notes[0])?, input(&self.notes[1])?],
            outputs: dest.map(|(a, v)| {
                OutputNote::new(a.pk, v, Digest::hash_bytes(&[CHAIN, b"out", &random()]))
            }),
            fee,
            ct_digest: Digest::from_bytes(&[0; 32])?,
        };
        let mut ct = Vec::new();
        for (i, (addr, _)) in dest.iter().enumerate() {
            let c =
                encrypt_note(&addr.ek, &w.output_note(i)?, &pad_memo("")?, &random())?.to_bytes();
            ensure!(c.len() == CT, "ciphertext length");
            ct.extend_from_slice(&c);
        }
        w.ct_digest = Digest::from_bytes(&ct_digest(&[&ct[..CT], &ct[CT..]]))?;
        let proof = self.prover.prove_submission(vec![w])?;
        Ok(encode(false, &proof, &ct))
    }
}
fn actor(r: &mut impl Read, w: &mut impl Write) -> Result<()> {
    let meter = Meter::start();
    let key = SpendingKey::random(&mut rand::rng());
    let notes = [40, 60]
        .into_iter()
        .map(|v| Note::random(&mut rand::rng(), key.pk(), v))
        .collect::<Result<Vec<_>, _>>()?;
    let mut hello = key.address().to_bytes();
    for n in &notes {
        hello.extend_from_slice(&n.commitment().to_bytes());
    }
    let mut wallet = Wallet {
        key,
        notes,
        prover: WalletProver::new(1)?,
    };
    meter.finish("wallet_setup");
    write_frame(w, &hello)?;
    let genesis = fixed_words(&read_frame(r)?)?;
    let peer = Address::from_bytes(&read_frame(r)?)?;
    let meter = Meter::start();
    let submission = wallet.pay(&genesis, 1, genesis_parent(), &peer)?;
    meter.finish("wallet_create");
    write_frame(w, &submission)?;
    // Public compact history comes only after successful validation by the selected local source.
    let raw = read_frame(r)?;
    if raw.is_empty() {
        return Ok(());
    }
    ensure!(raw.len() == 4 * (32 + CT), "two-wallet receipts");
    let meter = Meter::start();
    let mut leaves = genesis.clone();
    let mut received = Vec::new();
    for row in raw.chunks_exact(32 + CT) {
        let cm = Digest::from_slice(&row[..32])?;
        leaves.push(cm);
        let ct = NoteCiphertext::from_bytes(&row[32..])?;
        if let Ok(hit) = try_receive(&wallet.key.incoming_viewing_key(), &ct, &cm) {
            received.push(hit.note);
        }
    }
    ensure!(received.len() == 2, "expected payment and change");
    wallet.notes = received;
    meter.finish("scan_four_receipts");
    write_frame(w, &[wallet.notes.len() as u8])?;
    let action = read_frame(r)?;
    if action.is_empty() { return Ok(()); }
    ensure!(action == b"spend", "wallet action");
    let meter = Meter::start();
    let parent = header(&genesis, 1, genesis_parent())?.0.block_hash();
    let follow = wallet.pay(&leaves, 2, parent, &peer)?;
    meter.finish("recipient_spend");
    write_frame(w, &follow)?;
    Ok(())
}

// All checks finish before a successful transition is published.
struct Ledger {
    leaves: Vec<Digest>,
    spent: HashSet<Word>,
    fees: u64,
    height: u32,
    parent: Digest,
}
impl Ledger {
    fn state_id(&self) -> [u8; 64] {
        let mut hash = Blake2b512::new();
        hash.update(CHAIN);
        hash.update(self.height.to_le_bytes());
        hash.update(self.parent.to_bytes());
        hash.update(self.fees.to_le_bytes());
        hash.update((self.leaves.len() as u64).to_le_bytes());
        for cm in &self.leaves {
            hash.update(cm.to_bytes());
        }
        let mut spent: Vec<_> = self.spent.iter().collect();
        spent.sort_unstable();
        for nf in spent {
            hash.update(nf);
        }
        hash.finalize().into()
    }

    fn apply(&mut self, raw: &[u8], inner: &Verifier, outer: &Verifier) -> Result<Vec<u8>> {
        let p = packet(raw)?;
        let proof = parse_proof(p.proof, if p.pair { outer } else { inner })?;
        let anchor = header(&self.leaves, self.height, self.parent)?
            .0
            .block_hash();
        let e = effects(&p, &proof, anchor, self.height)?;
        ensure!(e.spent.is_disjoint(&self.spent), "spent");
        ensure!(
            e.added.iter().all(|cm| !self.leaves.contains(cm)),
            "existing commitment"
        );
        let fees = self
            .fees
            .checked_add(e.fees)
            .context("ledger fee overflow")?;
        let height = self.height.checked_add(1).context("height overflow")?;
        let mut history = Vec::new();
        for (cm, cipher) in e.added.iter().zip(p.ciphertexts.chunks_exact(CT)) {
            history.extend_from_slice(&cm.to_bytes());
            history.extend_from_slice(cipher);
        }
        self.leaves.extend(e.added);
        self.spent.extend(e.spent);
        self.fees = fees;
        self.parent = anchor;
        self.height = height;
        Ok(history)
    }
}
fn main() -> Result<()> {
    std::panic::set_hook(Box::new(|_| {}));
    let mode = std::env::args().nth(1).context("role required")?;
    let (mut r, mut w) = (io::stdin().lock(), io::stdout().lock());
    if mode == "wallet" {
        return actor(&mut r, &mut w);
    }
    let meter = Meter::start();
    let inner = verifier()?;
    let (data, targets) = wrapper(&inner)?;
    let outer = data.verifier_data();
    ensure!(
        outer.common.config.zero_knowledge && inner.common.config.zero_knowledge,
        "hiding wrappers"
    );
    // Verifier keys are generated from the installed version, independently of all incoming frames.
    meter.finish("registered_setup");
    write_frame(&mut w, &serialize_verifier_data(&inner, "one")?)?;
    write_frame(&mut w, &serialize_verifier_data(&outer, "pair")?)?;
    let genesis = fixed_words(&read_frame(&mut r)?)?;
    ensure!(
        genesis.len() == 4
            && genesis
                .iter()
                .map(|v| v.to_bytes())
                .collect::<HashSet<_>>()
                .len()
                == 4,
        "trusted genesis"
    );
    let parent = genesis_parent();
    if mode == "builder" {
        let meter = Meter::start();
        let anchor = header(&genesis, 1, parent)?.0.block_hash();
        let mut pw = PartialWitness::new();
        let mut sidecars = Vec::new();
        let mut used = HashSet::new();
        for t in &targets {
            let raw = read_frame(&mut r)?;
            let p = packet(&raw)?;
            ensure!(!p.pair, "inner scheme");
            let proof = parse_proof(p.proof, &inner)?;
            let e = effects(&p, &proof, anchor, 1)?;
            ensure!(e.spent.is_disjoint(&used), "builder conflict");
            used.extend(e.spent);
            pw.set_proof_with_pis_target(t, &proof)?;
            sidecars.extend_from_slice(p.ciphertexts);
        }
        let proof = data.prove(pw)?;
        meter.finish("verify_two_and_prove_pair");
        write_frame(&mut w, &encode(true, &proof, &sidecars))?;
        return Ok(());
    }
    ensure!(mode == "node", "unknown role");
    let mut ledger = Ledger {
        leaves: genesis,
        spent: HashSet::new(),
        fees: 0,
        height: 1,
        parent,
    };
    loop {
        let raw = read_frame(&mut r)?;
        if raw.is_empty() {
            break;
        }
        let meter = Meter::start();
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            ledger.apply(&raw, &inner, &outer)
        }))
        .unwrap_or_else(|_| Err(anyhow!("malformed proof")));
        meter.finish(if result.is_ok() {
            "accepted"
        } else {
            "rejected"
        });
        let mut reply = vec![u8::from(result.is_ok())];
        for n in [
            ledger.height as u64,
            ledger.leaves.len() as u64,
            ledger.spent.len() as u64,
            ledger.fees,
        ] {
            reply.extend_from_slice(&n.to_le_bytes());
        }
        reply.extend_from_slice(&ledger.state_id());
        if let Ok(history) = result {
            reply.extend_from_slice(&history);
        }
        write_frame(&mut w, &reply)?;
    }
    Ok(())
}
