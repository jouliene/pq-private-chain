//! Public-only complete distinct-payment block/archival/catch-up discriminator.
mod fixture;mod inspect;mod metrics;mod snapshot;
use fixture::{Result,need,ledger};
use ledger_cp03::{CachePolicy,Error,EvictionProgress,Ledger,LocalArchive,ReconcileProgress,StoredBlock};
use metrics::{Span,measure};
use serde_json::{Value,json};
use std::{fs,io::Cursor,path::Path};

fn bytes(b:&StoredBlock)->u64{b.bodies.iter().map(|v|v.len()as u64).sum()}
fn queue(l:&Ledger,db:&Path,rows:&mut Vec<Value>,stage:&str,ram:u64)->Result<()> {
    let u=ledger(l.cache_usage())?;let s=snapshot::snapshot(db)?;
    rows.push(json!({"stage":stage,"retained_public_fixture_body_bytes_in_RAM":ram,
        "cached_bytes":u.cached_bytes,"unexported_bytes":u.unexported_bytes,"pending_export_rows":s.pending(),
        "archive_objects":s.objects(),"archive_committed_bytes":u.archive_committed_bytes,
        "scope":"quiescent actual DB queues and retained public oracle bytes; not a WAN ingress queue or peak"}));Ok(())
}
fn publish(l:&mut Ledger,a:&mut LocalArchive,rows:&mut Vec<Value>,db:&Path,n:usize)->Result<()> {
    let old=ledger(l.cache_usage())?;
    let span=Span::start()?;let mut session=ledger(l.archive_session(a))?;let r=session.append();
    span.finish(rows,&format!("block{n}-append-reserve-reconcile-verify-fsync"),&r)?;
    let pending=ledger(r)?.ok_or("nonempty pending publication")?;
    let p=ledger(measure(rows,&format!("block{n}-publish-evict-commit"),||pending.publish())?)?;
    need(p.objects==16 && p.bytes==old.unexported_bytes+16*68+if n==1 {148}else{0},"sixteen exact published objects/framing")?;
    drop(session);
    for _ in 0..3 {
        if ledger(l.cache_usage())?.cached_bytes==0{break;}
        let e=ledger(measure(rows,"bounded-extra-eviction",||l.evict_oldest_step())?)?;
        need(matches!(e,EvictionProgress::Freed{..}),"eviction progresses")?;
    }
    let u=ledger(l.cache_usage())?;let s=snapshot::snapshot(db)?;
    need(u.cached_bytes==0 && u.unexported_bytes==0 && s.pending()==0 && s.objects()==n*16,"acknowledged archive and zero cache/pending")?;
    need(p.evicted_rows==16 && p.evicted_bytes==old.unexported_bytes,"publication itself evicts all16 at watermark0")?;
    Ok(())
}
fn run(rows:&mut Vec<Value>,queues:&mut Vec<Value>,details:&mut Value,stage:&mut &'static str)->Result<()> {
    let args:Vec<_>=std::env::args_os().collect();need(args.len()==4,"WORKLOAD APPROVED_SHA256 NEW_WORKDIR")?;
    need(std::env::var_os("CP03_ARCHIVE_CRASH_POINT").is_none() && std::env::var_os("CP03_LEDGER_CRASH_POINT").is_none(),"default no fault hooks")?;
    *stage="operator-input";
    let i=measure(rows,"manifest-and-genesis-intake",||fixture::inputs(Path::new(&args[1]),args[2].to_str().ok_or("SHA argument")?))??;
    let work=Path::new(&args[3]);need(work.is_absolute(),"absolute new workdir")?;
    fs::create_dir(work).map_err(|_|"exclusive workdir")?;
    let db=work.join("source.db");let ap=work.join("source-archive");let dst=work.join("catchup.db");
    let max_block=16*ledger_cp03::history_codec::BODY_MAX as u64;
    let policy=ledger(CachePolicy::new(max_block,128*1024*1024))?;
    need(policy.watermark()==0,"watermark zero")?;
    *stage="source-cold-setup";
    let mut l=ledger(measure(rows,"source-create-prepare-registry-provider",||Ledger::create_with_archive_policy(&db,i.chain,&i.genesis,policy))?)?;
    let mut a=ledger(measure(rows,"source-open-local-archive",||LocalArchive::open_for(&l,&ap))?)?;
    need(ledger(measure(rows,"source-initial-reconcile",||l.archive_session(&mut a)?.reconcile())?)?==ReconcileProgress::Clean,"clean initial archive")?;
    let mut originals:Vec<StoredBlock>=Vec::new();
    *stage="credit-positive-pipeline";
    let pipeline=Span::start()?;
    let first=measure(rows,"credit16-file-hash-bounded-intake",||fixture::block(&i,0))??;
    let admitted=ledger(measure(rows,"credit16-atomic-admit-durable",||l.apply_expected_block(&first.header,&first.bodies))?)?;
    need(admitted.header==first.header && admitted.head.height==1 && admitted.head.leaf_count==32,"credit parent state")?;
    originals.push(first);queue(&l,&db,queues,"credit-admitted-pending",bytes(&originals[0]))?;
    publish(&mut l,&mut a,rows,&db,1)?;
    pipeline.finish(rows,"credit16-positive-pipeline-INCLUSIVE-summary",&Ok::<(),Error>(()))?;

    *stage="late-invalid-proof-control";
    let ordinary_control=measure(rows,"negative-ordinary16-public-input-intake",||fixture::block(&i,1))??;
    let mut invalid=ordinary_control.bodies.clone();
    let p=ledger_cp03::history_codec::body::parse_full(&invalid[15]).map_err(|_|"negative source parse")?;
    let offset=invalid[15].len()-p.proof().len();
    need(p.proof().starts_with(b"CPFRI003") && p.proof().len()>206+4+64,"opaque trace commitment exists")?;
    // Keep the public statement/envelopes/lengths intact; mutate an opaque proof
    // commitment digest, not canonical field data or the expected block header.
    invalid[15][offset+206+4]^=1;
    let before=snapshot::snapshot(&db)?;
    let bad=measure(rows,"ordinary16-last-proof-negative-atomic-admit",||l.append_local_block(&invalid))?;
    need(bad.as_ref().err()==Some(&Error::Proof),"last real proof rejection")?;
    need(before.all_equal(&snapshot::snapshot(&db)?),"all14 tables schema version unchanged after proof failure")?;
    need(ledger(l.head())?.height==1,"no partial ordinary block")?;
    drop(invalid);drop(ordinary_control);drop(before);

    *stage="ordinary-positive-pipeline";
    let pipeline=Span::start()?;
    // Actual positive intake is remeasured after the control; page cache is not
    // cleared. Prior negative verification/caches are disclosed, not hidden.
    let second=measure(rows,"ordinary16-file-hash-bounded-intake",||fixture::block(&i,1))??;
    let b=ledger(measure(rows,"ordinary16-atomic-admit-durable",||l.apply_expected_block(&second.header,&second.bodies))?)?;
    need(b.header==second.header && fixture::head(b.head)==i.endpoint,"exact producer endpoint")?;
    originals.push(second);
    let total: u64=originals.iter().map(bytes).sum();
    queue(&l,&db,queues,"ordinary-admitted-pending",total)?;
    publish(&mut l,&mut a,rows,&db,2)?;
    pipeline.finish(rows,"ordinary16-positive-pipeline-INCLUSIVE-summary",&Ok::<(),Error>(()))?;
    queue(&l,&db,queues,"both-blocks-archived-evicted",total)?;
    for n in 1..=2 {need(l.full_block(n).as_ref().err()==Some(&Error::HistoryUnavailable),"cached path really unavailable")?;}
    let stable=snapshot::snapshot(&db)?;
    let archive=inspect::archive(&i,&originals,&db,&ap)?;

    *stage="fresh-public-catchup";
    let catch_policy=ledger(CachePolicy::new(2*max_block,128*1024*1024))?;
    let mut fresh=ledger(measure(rows,"catchup-create-prepare-registry-provider",||Ledger::create_with_archive_policy(&dst,i.chain,&i.genesis,catch_policy))?)?;
    let catch_span=Span::start()?;
    for n in 1..=2 {
        let fetched=ledger(measure(rows,&format!("archive-fetch-and-fresh-historical-verify-block{n}"),||l.full_block_with_archive(n,&a))?)?;
        let original=&originals[n as usize-1];
        need(fetched.header==original.header && fetched.bodies==original.bodies,"all fetched public bytes exactly match originals")?;
        let got=ledger(measure(rows,&format!("fresh-ledger-catchup-verify-state-commit-block{n}"),||fresh.apply_expected_block(&fetched.header,&fetched.bodies))?)?;
        need(got.header==original.header,"catchup exact original header")?;
        queue(&fresh,&dst,queues,&format!("catchup-applied-block{n}"),total+bytes(&fetched))?;
    }
    catch_span.finish(rows,"fresh-public-catchup-INCLUSIVE-summary",&Ok::<(),Error>(()))?;
    need(stable.all_equal(&snapshot::snapshot(&db)?),"archive reads preserve source all14 state")?;
    let fresh_state=snapshot::snapshot(&dst)?;
    need(stable.canonical_equal(&fresh_state),"fresh independent canonical state/body identities equal")?;
    need(fixture::head(ledger(fresh.head())?)==i.endpoint,"fresh exact endpoint")?;
    let mut scan=Vec::new();let endpoint=ledger(measure(rows,"export-complete-reduced-scan",||l.export_scan(&mut scan))?)?;
    let mut checked=Vec::new();
    let c=ledger(measure(rows,"check-complete-reduced-scan",||ledger_cp03::check_scan(i.chain,&i.genesis,Cursor::new(&scan),endpoint.height,endpoint.id,&mut checked))?)?;
    need(c.height()==2 && c.leaf_count()==64 && checked==scan,"scan completeness exact endpoint")?;
    *details=json!({"workload_sha256":i.manifest_sha256,"blocks":2,"bodies_per_block":16,"new_genuine_bodies":32,
        "input_body_bytes":total,"negative_last_proof_rejected":true,"negative_all14_unchanged":true,
        "same_canonical_fresh_state":true,"all32_archive_body_bytes_matched":true,"endpoint":i.endpoint,
        "source_policy":{"hard_bytes":max_block,"watermark":0,"archive_limit_bytes":128*1024*1024},
        "catchup_policy":{"hard_bytes":2*max_block,"archive_limit_bytes":128*1024*1024},
        "source_rows":stable.row_counts(),"catchup_rows":fresh_state.row_counts(),"source_db_physical":snapshot::physical(&db)?,
        "catchup_db_physical":snapshot::physical(&dst)?,"archive":archive,"scan_bytes":scan.len(),
        "cache_condition":"uncontrolled page cache; source inputs/negative predecessor and full public oracle retained; no cold-page claim",
        "scope":"sequential local persistent APIs and disk archive; repeated genuine verification, no cached verdict; no WAN, annual capacity, private recovery or PQ/privacy theorem"});
    *stage="complete";Ok(())
}
fn main(){
    let(mut rows,mut queues,mut details,mut stage)=(Vec::new(),Vec::new(),Value::Null,"start");
    let result=run(&mut rows,&mut queues,&mut details,&mut stage);
    let value=json!({"format":"CP03-DISTINCT-PUBLIC-ROLE01","succeeded":result.is_ok(),"stage":stage,"error":result.as_ref().err(),
        "operations":rows,"queues":queues,"details":details,"private_inputs":false,"whole_resource_acceptance":false});
    println!("{}",serde_json::to_string_pretty(&value).expect("public JSON"));
    if result.is_err(){std::process::exit(1);}
}
