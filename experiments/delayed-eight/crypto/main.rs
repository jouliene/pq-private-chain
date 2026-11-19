//! Eight independent direct proof verifications, with an explicit authenticated active prefix.
mod codec;
mod inner;

use anyhow::{anyhow, ensure, Context, Result};
use codec::{checked_slots, effects, packet, read_frame, write_frame, Meter, Packet, CT};
use inner::Verifier;
use plonky2::field::types::{Field, PrimeField64};
use plonky2::fri::FriReductionStrategy;
use plonky2::iop::target::BoolTarget;
use plonky2::iop::witness::{PartialWitness, WitnessWrite};
use plonky2::plonk::circuit_builder::CircuitBuilder;
use plonky2::plonk::proof::ProofWithPublicInputsTarget;
use plonky2::util::serialization::DefaultGateSerializer;
use qnero_aggregator::recursive::add_recursive_verifiers;
use qnero_aggregator::Proof;
use qnero_circuit::config::qnero_private_batch_circuit_config;
use qnero_circuit::{C, D, F};
use std::{fs, io, path::Path};

const WIDTH: usize = 8;
const PI: usize = 26;
const TAG: u64 = 0x443843310001;

struct Targets {
    active: Vec<BoolTarget>,
    proofs: Vec<ProofWithPublicInputsTarget<D>>,
}

fn circuit(inner: &Verifier) -> Result<(CircuitBuilder<F,D>,Targets)> {
    let mut conf=qnero_private_batch_circuit_config();
    conf.zero_knowledge=false;
    conf.num_wires=135;
    conf.num_routed_wires=60;
    conf.num_challenges=2;
    conf.security_bits=128;
    conf.fri_config.rate_bits=5;
    conf.fri_config.cap_height=4;
    conf.fri_config.num_query_rounds=26;
    conf.fri_config.proof_of_work_bits=0;
    conf.fri_config.reduction_strategy=FriReductionStrategy::ConstantArityBits(2,3);
    ensure!(!conf.zero_knowledge && inner.common.config.zero_knowledge && inner.common.fri_params.leaf_hiding && D==2,"public aggregation profile and hiding direct input");
    let mut b=CircuitBuilder::new(conf);
    let proofs=add_recursive_verifiers(&mut b,&inner.common,&inner.verifier_only,WIDTH)?;
    let active:Vec<_>=(0..WIDTH).map(|_|b.add_virtual_bool_target_safe()).collect();
    let one=b.one();
    b.connect(active[0].target,one);
    for i in 1..WIDTH {
        b.conditional_assert_eq(active[i].target,active[i-1].target,one);
        let inactive=b.not(active[i]);
        for (left,right) in proofs[i-1].public_inputs.iter().zip(&proofs[i].public_inputs) {
            b.conditional_assert_eq(inactive.target,*left,*right);
        }
    }
    let tag=b.constant(F::from_canonical_u64(TAG));
    let count=b.add_many(active.iter().map(|f|f.target));
    b.register_public_input(tag);
    b.register_public_input(count);
    for p in &proofs {
        ensure!(p.public_inputs.len()==PI,"inner shape");
        b.register_public_inputs(&p.public_inputs);
    }
    Ok((b,Targets{proofs,active}))
}

fn keybytes(v:&Verifier)->Result<Vec<u8>> {
    ensure!(!v.common.config.zero_knowledge && !v.common.fri_params.leaf_hiding && v.common.num_public_inputs==2+WIDTH*PI,"outer shape");
    v.to_bytes(&DefaultGateSerializer).map_err(|_|anyhow!("outer verifier serialization"))
}

fn decode_outer(dir:&Path)->Result<Verifier> {
    let raw=fs::read(dir.join("eight.vk"))?;
    let v=Verifier::from_bytes(raw.clone(),&DefaultGateSerializer).map_err(|_|anyhow!("verifier decoding"))?;
    ensure!(keybytes(&v)?==raw,"noncanonical verifier key");
    Ok(v)
}

fn check(v:&Verifier,raw:&[u8])->Result<Vec<u8>> {
    ensure!(raw.len()>=9 && raw.len()<=2*1024*1024 && &raw[..4]==b"D8C1","certificate framing");
    let k=usize::from(raw[4]);
    ensure!((1..=WIDTH).contains(&k),"certificate occupancy");
    let n=u32::from_le_bytes(raw[5..9].try_into()?) as usize;
    ensure!(n>0 && 9+n+2*CT*k==raw.len(),"certificate size");
    let bytes=&raw[9..9+n];
    let proof=Proof::from_bytes(bytes.to_vec(),&v.common)?;
    ensure!(proof.to_bytes()==bytes,"noncanonical outer proof");
    let all=&proof.public_inputs;
    ensure!(all.len()==2+WIDTH*PI && all[0].to_canonical_u64()==TAG && all[1].to_canonical_u64()==k as u64,"authenticated occupancy");
    let fields=&all[2..];
    for row in fields[k*PI..].chunks_exact(PI) {
        ensure!(row==&fields[(k-1)*PI..k*PI],"invalid padded statement");
    }
    v.verify(proof.clone())?;
    let sidecar=Packet{arity:k,proof:bytes,cts:&raw[9+n..]};
    checked_slots(&sidecar,&fields[..k*PI])
}

fn main()->Result<()> {
    let mut args=std::env::args_os().skip(1);
    let mode=args.next().context("mode")?;
    let directory=args.next().context("approved key directory")?;
    let dir=Path::new(&directory);
    let (mut r,mut w)=(io::stdin().lock(),io::stdout().lock());
    if mode=="verify" {
        let t=Meter::start();
        let vk=decode_outer(dir)?;
        t.finish("certificate_verifier_setup");
        write_frame(&mut w,b"READY")?;
        loop {
            let raw=read_frame(&mut r)?;
            if raw.is_empty(){return Ok(())}
            let t=Meter::start();
            match check(&vk,&raw) {
                Ok(x)=>{let mut reply=vec![b'1'];reply.extend(x);write_frame(&mut w,&reply)?;t.finish("certificate_verify");}
                Err(_)=>{write_frame(&mut w,b"0")?;t.finish("certificate_rejected");}
            }
        }
    }
    let setup=Meter::start();
    let inner=inner::load(dir)?;
    let (b,targets)=circuit(&inner)?;
    if mode=="register" {
        let gates=b.num_gates();
        let v=b.build_verifier::<C>();
        let bs=keybytes(&v)?;
        ensure!(!dir.join("eight.vk").exists(),"fresh key directory");
        fs::write(dir.join("eight.vk"),bs)?;
        println!("{{\"domain\":{},\"outer_gates_before_blinding\":{},\"degree_bits\":{},\"public_inputs\":{},\"folds\":{:?},\"inner_degree_bits\":{},\"inner_folds\":{:?}}}",TAG,gates,v.common.degree_bits(),v.common.num_public_inputs,v.common.fri_params.reduction_arity_bits,inner.common.degree_bits(),inner.common.fri_params.reduction_arity_bits);
        setup.finish("registration");
        return Ok(())
    }
    ensure!(mode=="builder","unknown operation");
    let data=b.build::<C>();
    ensure!(keybytes(&data.verifier_data())?==fs::read(dir.join("eight.vk"))?,"derived outer verifier mismatches registration");
    setup.finish("certificate_builder_setup");
    write_frame(&mut w,b"READY")?;
    loop {
        let count=read_frame(&mut r)?;
        if count.is_empty(){return Ok(())}
        if count.len()!=1 || !(1..=WIDTH as u8).contains(&count[0]) {
            write_frame(&mut w,b"0")?;
            continue
        }
        let k=usize::from(count[0]);
        let items=(0..k).map(|_|read_frame(&mut r)).collect::<Result<Vec<_>>>()?;
        let prep=Meter::start();
        let input=(||->Result<_> {
            let mut proofs=Vec::new();
            let mut cts=Vec::new();
            let mut nfs=std::collections::HashSet::new();
            let mut cms=std::collections::HashSet::new();
            for raw in &items {
                let p=packet(raw)?;
                let proof=inner::verify(&inner,p.proof)?;
                let checked=effects(&p,&proof)?;
                for word in checked[36..100].chunks_exact(32) {ensure!(nfs.insert(word.to_vec()),"duplicate input");}
                for word in checked[100..164].chunks_exact(32) {ensure!(cms.insert(word.to_vec()),"duplicate output");}
                cts.extend_from_slice(p.cts);
                proofs.push(proof);
            }
            let mut witness=PartialWitness::new();
            for i in 0..WIDTH {
                witness.set_bool_target(targets.active[i],i<k)?;
                witness.set_proof_with_pis_target(&targets.proofs[i],&proofs[i.min(k-1)])?;
            }
            Ok((witness,cts))
        })();
        let Ok((witness,cts))=input else {prep.finish("source_rejected");write_frame(&mut w,b"0")?;continue};
        prep.finish("source_verify_assign");
        let t=Meter::start();
        let proof=data.prove(witness)?.to_bytes();
        let mut out=b"D8C1".to_vec();
        out.push(k as u8);
        out.extend((proof.len() as u32).to_le_bytes());
        out.extend(proof);
        out.extend(cts);
        t.finish("certificate_prove");
        write_frame(&mut w,&out)?;
    }
}
