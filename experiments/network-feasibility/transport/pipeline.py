#!/usr/bin/env python3
"""Fixed eight-batch (or three-batch diagnostic) bounded Gate2 experiment."""
import argparse,copy,importlib.util,json,os,re,signal,sys,time,resource
from pathlib import Path
sys.dont_write_bytecode=True
HERE=Path(__file__).resolve().parent;sys.path.insert(0,str(HERE))
import campaign as g1
import prepare_pipeline as prep
import oracle
from prepare import sha,need
ROOT=HERE.parents[2]
STATES=('future','pending','uploading','ready','validating','accepted')
class Offers:
 """Only public batch identities and counters; no payload/secret queue."""
 def __init__(self,objects,offsets,epoch_ns,cutoff_ns=None,clock=None):
  self.objects=objects;self.epoch_ns=epoch_ns;self.cutoff_ns=cutoff_ns;self.clock=clock;self.late_events=[];self.rows={f'ordinary{i+1}':{'state':'future','offer_due_ns':epoch_ns+round(t*1e9),'frame_bytes':objects[f'ordinary{i+1}']['bytes']}for i,t in enumerate(offsets)};self.events=[];self.peaks={k:0 for k in STATES};self.peak_bytes={k:0 for k in STATES};self.peak_credits=0;self.check()
 def transition(self,name,state,now):
  actual=self.clock()if self.clock is not None else now
  if self.cutoff_ns is not None and actual>=self.cutoff_ns:
   self.late_events.append({'batch':name,'requested_to':state,'event_receipt_ns':now,'actual_controller_ns':actual,'state_unchanged':self.rows[name]['state']});return False
  row=self.rows[name];old=row['state'];now=actual
  if state=='uploading':need(self.credits()<2 and self.counts()['uploading']==0,'reserve bounded upload credit')
  if state=='validating':need(self.counts()['validating']==0,'one validator frame')
  if state=='pending':need(self.counts()['pending']<8,'finite pending queue')
  need((old,state)in[('future','pending'),('pending','uploading'),('uploading','ready'),('ready','validating'),('validating','accepted')],'offer transition')
  row['state']=state;row[state+'_observed_ns']=now;self.events.append({'batch':name,'from':old,'to':state,'observed_ns':now,'offer_due_ns':row['offer_due_ns'],'frame_bytes':row['frame_bytes']});self.check();return True
 def due(self,now):
  for name,row in self.rows.items():
   if row['state']=='future'and row['offer_due_ns']<=now:
    if not self.transition(name,'pending',now):break
 def counts(self):return {state:sum(row['state']==state for row in self.rows.values())for state in STATES}
 def credits(self):return sum(row['state']in('uploading','ready','validating')for row in self.rows.values())
 def check(self):
  c=self.counts();need(sum(c.values())==len(self.rows)and c['pending']<=8 and c['uploading']<=1 and c['validating']<=1 and self.credits()<=2,'bounded disjoint offer states')
  for state,n in c.items():self.peaks[state]=max(self.peaks[state],n);self.peak_bytes[state]=max(self.peak_bytes[state],sum(row['frame_bytes']for row in self.rows.values()if row['state']==state))
  self.peak_credits=max(self.peak_credits,self.credits())
 def next(self,state):return next((name for name,row in self.rows.items()if row['state']==state),None)
 def snapshot(self,at):
  self.check();due_unprocessed=[name for name,row in self.rows.items()if row['state']=='future'and row['offer_due_ns']<=at];return {'scheduled_due_blocks':sum(row['offer_due_ns']<=at for row in self.rows.values()),'due_but_not_materialized_ids':due_unprocessed,'boundary_monotonic_ns':at,'observed_snapshot_monotonic_ns':time.monotonic_ns(),'states':copy.deepcopy(self.rows),'counts':self.counts(),'frame_bytes_by_state':{s:sum(r['frame_bytes']for r in self.rows.values()if r['state']==s)for s in STATES},'reserved_or_unadmitted_credits':self.credits(),'queue_peaks':dict(self.peaks),'queue_byte_peaks':dict(self.peak_bytes),'peak_credits':self.peak_credits,'late_transitions_not_counted':copy.deepcopy(self.late_events),'offered_blocks':sum(r['state']!='future'for r in self.rows.values()),'accepted_blocks':sum(r['state']=='accepted'for r in self.rows.values())}

def profile(value,n,batches):
 need(value['format']=='CP04-GATE2-PROFILE01','profile schema')
 if(n,batches)==(96,8):offsets=value['schedule']['ordinary_offer_offsets_seconds'];end=value['schedule']['fixed_observation_end_seconds'];down=value['restart']['validator_down_seconds'];outer=value['network_campaign_outer_watchdog_seconds'];expected=([0,0,30.27456,60.54912,90.82368,121.09824,151.3728,181.64736],363.29472,90.82368,600)
 else:
  d=value['diagnostic_network_profile'];offsets=d['offer_offsets_seconds'];end=d['fixed_observation_end_seconds'];down=d['stop_after_second_ordinary_ack_seconds'];outer=d['outer_watchdog_seconds'];expected=([0,0,.5],12,1.5,120)
 need((offsets,end,down,outer)==expected,'exact declared timing profile');need(value['research_resources']['fresh_validator_retain_raw_body_quota_bytes']==2147483648 and value['queues']['reserved_or_archive_durable_unadmitted_frames_max']==2 and value['queues']['finite_source_pending_ids_max']==8,'exact resource profile')
 return offsets,end,down,outer

def namespace_check(role,binary,hidden):
 def descendants(pid):
  yield pid
  try:kids=Path(f'/proc/{pid}/task/{pid}/children').read_text().split()
  except FileNotFoundError:return
  for child in kids:yield from descendants(int(child))
 candidates=[]
 for pid in descendants(role.p.pid):
  try:
   if Path(f'/proc/{pid}/exe').resolve()==Path(binary).resolve():candidates.append(pid)
  except FileNotFoundError:pass
 need(len(candidates)==1,'actual native host PID');pid=candidates[0];need(os.readlink(f'/proc/{pid}/ns/pid')!=os.readlink('/proc/self/ns/pid'),'private native PID namespace')
 need(all(not Path('/proc/'+str(pid)+'/root'+str(p)).exists()for p in hidden),'actual new producer/public proof denial')
 return {'host_pid':pid,'private_pid_namespace':True,'denied_known_files':len(hidden),'actual_checked_at_ns':time.monotonic_ns()}

def main():
 p=argparse.ArgumentParser();p.add_argument('--label',required=True);p.add_argument('--installation',type=Path,required=True);p.add_argument('--approve-installation',required=True);p.add_argument('--approve-source',required=True);p.add_argument('--build-label',required=True);p.add_argument('--approve-build',required=True);p.add_argument('--workload',type=Path,required=True);p.add_argument('--approve-workload',required=True);p.add_argument('--approve-profile',required=True);a=p.parse_args()
 need(re.fullmatch('[a-z0-9-]+',a.label)and{0,1,2}<=os.sched_getaffinity(0),'label/CPU profile')
 source=HERE/'SOURCE.json';need(sha(source)==a.approve_source,'source approval');s=g1.load(source)
 def pins():
  for name,h in s['files'].items():need(sha(HERE/name)==h,'source drift '+name)
 pins();pp=ROOT/'experiments/network-feasibility/GATE2_PROFILE.json';need(sha(pp)==a.approve_profile,'explicit declared profile approval');decl=g1.load(pp)
 spec=importlib.util.spec_from_file_location('public_common',ROOT/'scripts/common.py');common=importlib.util.module_from_spec(spec);spec.loader.exec_module(common);inst=common.load_installation(a.installation.resolve(),a.approve_installation);need(Path(inst['repository'])==ROOT,'same repository')
 bp=HERE/'.work'/a.build_label/'BUILD.json';need(sha(bp)==a.approve_build,'actual build approval');build=g1.load(bp);need(build['source_sha256']==a.approve_source and build['installation_sha256']==a.approve_installation,'same source/installation build')
 def buildpins():
  for name,h in{**build['compiled_inputs'],**build['runtime'],build['binary']:build['binary_sha256'],build['own_manifest']:build['own_manifest_sha256'],build['lock_path']:build['lock_sha256']}.items():need(sha(name)==h,'build/runtime drift')
 buildpins();work=HERE/'.work'/a.label;work.mkdir();producer=work/'producer';archive=work/'archive';validator=work/'validator';archive.mkdir();validator.mkdir();roles=[];receipts=[];result={'passed':False};prepared=None;controller_start=time.monotonic();controller_usage=resource.getrusage(resource.RUSAGE_SELF)
 # The outer deadline includes preparation/setup and never changes offer timing.
 raw=g1.load(a.workload);offsets,observation,down,outer=profile(decl,raw['batch_size'],raw['ordinary_batch_count']);outer_deadline=controller_start+outer;env=common.controlled_env();env.update(inst['proof_environment']);env.update(RAYON_NUM_THREADS='1',RUST_BACKTRACE='0');python=Path(sys.executable).resolve();need(str(python)in inst['pins'],'approved Python')
 def watch():
  need(time.monotonic()<outer_deadline,'outer watchdog')
  for role in roles:
   if not role.done:role.observe()
  if prepared:
   local=oracle.disk(producer);external=prepared['charged_external_producer_disk'];combined={k:local[k]+external[k]for k in local};need(max(combined['logical_bytes'],combined['allocated_bytes'])<=8*1024**3,'ALL producer copies disk ceiling');result['producer_charged_disk_current']=combined
 def newrole(name,cmd,cpu,directory):
  role=g1.Role(name,cmd,cpu,env,directory,outer_deadline,watch);roles.append(role);return role
 def sender(name):
  o=prepared['objects'][name];return newrole('producer-'+name,[python,HERE/'sender.py','--object',o['path'],'--sha256',o['sha256'],'--bytes',o['bytes'],'--kind',o['kind'],'--port',port],0,producer)
 def sendcmd(role,c):role.p.stdin.write(json.dumps(c,separators=(',',':')).encode()+b'\n');role.p.stdin.flush()
 def cmd(name,op='apply'):
  o=prepared['objects'][name];return {'op':op,'sha256':o['sha256'],'bytes':o['bytes'],'tag':name}
 def native_result(row):need(row['error']is None,'native command error');return row['result']
 def reap(role):
  receipt=role.finish();receipts.append(receipt);return receipt
 try:
  prepared=prep.prepare(a.workload,a.approve_workload,producer,inst['source_root']);g1.save(work/'PREPARED.json',prepared);n=prepared['batch_size'];batches=prepared['ordinary_batch_count'];watch()
  for d in[archive,validator,producer,work,work.parent,HERE]:fd=os.open(d,os.O_RDONLY|os.O_DIRECTORY);os.fsync(fd);os.close(fd)
  ar=newrole('archive',[python,'-I',HERE/'archive.py','--root',archive],1,archive);ready=ar.drain(lambda row:row.get('ready')is True);port=ready['port']
  for name in['genesis','funding']:reap(sender(name))
  denied=[a.workload.resolve().parent,producer.resolve(),archive.resolve(),Path(prepared['proof_public_root'])]
  for optional in[Path(inst['source_root'])/'experiments/cp03-private-cycle/evidence',ROOT/'experiments/architecture-feasibility']:
   if optional.is_dir():denied.append(optional)
  argv=['/usr/bin/bwrap','--die-with-parent','--unshare-pid','--ro-bind','/','/','--proc','/proc','--dev','/dev','--bind',str(validator),str(validator)]
  for d in denied:argv+=['--tmpfs',str(d)]
  argv+=['--',build['binary'],str(validator/'ledger.sqlite'),prepared['chain'],f'127.0.0.1:{port}','2147483648']
  hidden=[a.workload.resolve(),a.workload.resolve().parent/'producer.sqlite',Path(prepared['known_actual_new_proof']),Path(prepared['objects']['ordinary1']['path']),archive/(prepared['objects']['funding']['sha256']+'.blob')]
  v=newrole('validator-initial',argv,2,validator);v.drain(lambda row:row.get('ready')is True);result['namespace_checks']=[namespace_check(v,build['binary'],hidden)]
  result['initialization']=native_result(v.request(cmd('genesis','init')));result['funding']=native_result(v.request(cmd('funding')));need(result['funding']['accepted']is True and result['funding']['state']['hard_bytes']==2147483648,'funding/explicit2GiB quota')
  epoch=time.monotonic_ns();end=epoch+round(observation*1e9);offers=Offers(prepared['objects'],offsets,epoch,end,time.monotonic_ns);result.update(offer_epoch_monotonic_ns=epoch,observation_end_monotonic_ns=end,declared_observation_seconds=observation,declared_validator_down_seconds=down,declared_outer_seconds=outer,cleanup_grace_seconds=30 if n==96 else 10);events=[];late_actions=[];v_cursor=len(v.rows);u=None;upload_name=None;busy=None;phase='running';stopped_at=None;restart_not_before=None;blocked_at=None;blocked_ns=0;applies=[];native_totals=[]
  def before_end(kind,**details):
   at=time.monotonic_ns()
   if at>=end:late_actions.append({'kind':kind,'actual_controller_ns':at,**details});return None
   return at
  while True:
   now=time.monotonic_ns()
   if now>=end:
    result['deadline_snapshot']=offers.snapshot(end);result['deadline_phase']=phase;result['deadline_validator_command']=busy;result['deadline_sender_batch']=upload_name;result['deadline_reached_observed_ns']=now;result['deadline_rows_received_not_processed']=[{'received_ns':v.row_receipt_ns[i],'row':v.rows[i]}for i in range(v_cursor,len(v.rows))];break
   offers.due(now)
   # Nonblocking polling only: fixed offer/end clocks cannot wait inside a RPC.
   for role in [ar,v]+([u]if u is not None else[]):
    if not role.done:role.drain(timeout=0)
   now=time.monotonic_ns()
   if now>=end:continue
   if u is not None and os.waitid(os.P_PID,u.p.pid,os.WEXITED|os.WNOHANG|os.WNOWAIT)is not None:
    reap(u);offers.transition(upload_name,'ready',time.monotonic_ns());u=None;upload_name=None
   while v_cursor<len(v.rows):
    row=v.rows[v_cursor];received=v.row_receipt_ns[v_cursor];v_cursor+=1
    if received>=end or before_end('native_row_processing',received_ns=received,row=row)is None:continue
    if row.get('ready')is True and phase=='starting':
     result['namespace_checks'].append(namespace_check(v,build['binary'],hidden))
     if before_end('fresh_open_start')is not None:sendcmd(v,{'op':'open'});busy='open';phase='opening';events.append({'kind':'fresh_open_sent','at_ns':time.monotonic_ns()})
    elif row.get('op')=='apply':
     value=native_result(row);need(value['accepted']is True,'genuine pipeline rejection')
     if busy=='retry':
      need(value['retry_current_canonical']is True and value['state']['proof_attempts']==0,'retry must not verify/release credit')
      if before_end('retry_ack_transition',received_ns=received)is not None:result['retry']=value;events.append({'kind':'retry_ack','at_ns':received,'transport':value['transport']});busy=None;phase='running'
     else:
      name=busy;need(name in offers.rows,'active ordinary identity')
      if not offers.transition(name,'accepted',received):continue
      applies.append({'batch':name,'ack_monotonic_ns':received,'response':row});busy=None
      if name=='ordinary2'and before_end('stop_after_second_ack_start')is not None:sendcmd(v,{'op':'stop'});busy='stop';phase='stopping';events.append({'kind':'stop_after_second_ack_sent','at_ns':time.monotonic_ns()})
    elif row.get('op')=='open':
     result['reopen']=native_result(row);need(result['reopen']['block_id']==prepared['objects']['ordinary2']['block_id'],'same durable second tip')
     if before_end('retry_start_without_credit')is not None:sendcmd(v,cmd('ordinary2'));busy='retry';phase='retrying';events.append({'kind':'retry_sent_without_credit_change','at_ns':time.monotonic_ns()})
   if phase=='stopping'and os.waitid(os.P_PID,v.p.pid,os.WEXITED|os.WNOHANG|os.WNOWAIT)is not None:
    receipt=reap(v);native_totals.append(g1.native_lifetime(receipt));at=before_end('stopped_terminal_transition')
    if at is not None:stopped_at=at;restart_not_before=stopped_at+round(down*1e9);phase='stopped';busy=None;events.append({'kind':'validator_stopped_terminal','at_ns':stopped_at,'restart_not_before_ns':restart_not_before})
   if phase=='stopped'and time.monotonic_ns()>=restart_not_before:
    restart_at=before_end('validator_restart_start')
    if restart_at is not None:
     phase='starting';v=newrole('validator-restarted',argv,2,validator);v_cursor=0;result['actual_stopped_to_restart_seconds']=(restart_at-stopped_at)/1e9;events.append({'kind':'validator_restart_spawn','requested_ns':restart_at,'spawn_returned_ns':time.monotonic_ns()})
   now=time.monotonic_ns()
   if now>=end:continue
   pending=offers.next('pending');credit_blocked=pending is not None and offers.credits()>=2
   if credit_blocked and blocked_at is None:blocked_at=now;events.append({'kind':'credit_backpressure_start','at_ns':now})
   if not credit_blocked and blocked_at is not None:blocked_ns+=now-blocked_at;events.append({'kind':'credit_backpressure_end','at_ns':now});blocked_at=None
   if u is None and pending is not None and offers.credits()<2 and offers.transition(pending,'uploading',now):
    upload_name=pending
    if before_end('sender_start',batch=pending)is not None:u=sender(pending)
   if phase=='running'and busy is None:
    nextname=next((name for name,row in offers.rows.items()if row['state']!='accepted'),None)
    if nextname is not None and offers.rows[nextname]['state']=='ready'and before_end('validator_apply_start',batch=nextname)is not None:
     if offers.transition(nextname,'validating',time.monotonic_ns()):sendcmd(v,cmd(nextname));busy=nextname
   watch();time.sleep(.002)
  if blocked_at is not None:blocked_ns+=max(0,end-blocked_at)
  result['late_controller_actions_not_started']=late_actions;result['credit_backpressure_seconds_before_deadline']=blocked_ns/1e9;result['offer_events']=offers.events;result['role_events']=events;result['ordinary_ack_records_before_deadline']=applies
  # No more offer-state transitions after this immutable boundary. Teardown and
  # external SQL/byte oracles are outside the observed service interval.
  cleanup_start=time.monotonic();cleanup_end=min(outer_deadline,cleanup_start+result['cleanup_grace_seconds']);result['postdeadline_role_rows_start']={str(role.p.pid):len(role.rows)for role in roles};stop_sent=False
  if not v.done:sendcmd(v,{'op':'stop'});stop_sent=True
  if not ar.done:os.kill(ar.p.pid,signal.SIGTERM)
  while time.monotonic()<cleanup_end:
   active=[role for role in roles if not role.done]
   if not active:break
   for role in active:
    role.drain(timeout=0)
    if os.waitid(os.P_PID,role.p.pid,os.WEXITED|os.WNOHANG|os.WNOWAIT)is not None:
     receipt=reap(role)
     if role.name.startswith('validator'):native_totals.append(g1.native_lifetime(receipt))
   time.sleep(.002)
  for role in roles:
   if not role.done:receipts.append(role.cleanup())
  result['cleanup_wall_seconds']=time.monotonic()-cleanup_start;result['native_incarnations']=native_totals
  result['postdeadline_role_rows']={str(role.p.pid):role.rows[result['postdeadline_role_rows_start'][str(role.p.pid)]:]for role in roles}
  db=validator/'ledger.sqlite';source_db=a.workload.resolve().parent/'producer.sqlite';dest=oracle.snapshot(db,True);source_state=oracle.snapshot(source_db,True);retained=oracle.retained(db);result['external_afterdeadline_canonical_equal']=dest==source_state;result['retained_afterdeadline']=retained;g1.save(work/'CANONICAL_AFTER_DEADLINE.json',dest)
  rpc=[row for row in ar.rows if 'complete'in row];puts=[row for row in rpc if row.get('op')==1 and row.get('complete')and row['started_monotonic_ns']>=epoch];gets=[row for row in rpc if row.get('op')==2 and row.get('complete')and row['started_monotonic_ns']>=epoch];overlaps=[]
  rpc_overlaps=[];ordinary_names={o['sha256']:name for name,o in prepared['objects'].items()if name.startswith('ordinary')};accepted_at={row['batch']:row['ack_monotonic_ns']for row in applies}
  for put in puts:
   for get in gets:
    start=max(put['started_monotonic_ns'],get['started_monotonic_ns'],epoch);finish=min(put['finished_monotonic_ns'],get['finished_monotonic_ns'],end)
    if finish>start:rpc_overlaps.append({'put_sha256':put['object_sha256'],'get_sha256':get['object_sha256'],'start_ns':start,'end_ns':finish,'seconds':(finish-start)/1e9})
    # Decisive evidence is data-transfer overlap of different ordinary batches,
    # excluding a GET of a previously admitted tip (the deliberate retry).
    if put['object_sha256']==get['object_sha256']or put['object_sha256']not in ordinary_names or get['object_sha256']not in ordinary_names:continue
    if accepted_at.get(ordinary_names[get['object_sha256']],end)<=get['started_monotonic_ns']:continue
    start=max(put['body_transfer_started_ns'],get['body_transfer_started_ns'],epoch);finish=min(put['body_transfer_finished_ns'],get['body_transfer_finished_ns'],end)
    if finish>start:overlaps.append({'put_sha256':put['object_sha256'],'get_sha256':get['object_sha256'],'start_ns':start,'end_ns':finish,'seconds':(finish-start)/1e9,'scope':'Different ordinary batch data-transfer intervals; GET was not already admitted at its start, no ACK/metrics-tail overlap'})
  result['all_archive_RPC_overlap_intervals']=rpc_overlaps
  producer_wire=[row for role in roles if role.name.startswith('producer-')for row in role.rows if row.get('role')=='producer-transport'];native_wire=[row['result']['transport']for role in roles if role.name.startswith('validator')for row in role.rows if row.get('op')in('init','apply')and row.get('result')is not None and'transport'in row['result']];allput=[row for row in rpc if row.get('op')==1];allget=[row for row in rpc if row.get('op')==2]
  result['actual_application_byte_conservation']={'producer_sent':sum(row['application_sent']for row in producer_wire),'archive_put_received':sum(row['application_received']for row in allput),'archive_put_sent':sum(row['application_sent']for row in allput),'producer_received':sum(row['application_received']for row in producer_wire),'archive_get_sent':sum(row['application_sent']for row in allget),'validator_received':sum(row['application_received']for row in native_wire),'validator_sent':sum(row['application_sent']for row in native_wire),'archive_get_received':sum(row['application_received']for row in allget)}
  flows=result['actual_application_byte_conservation'];need(flows['producer_sent']==flows['archive_put_received']and flows['archive_put_sent']==flows['producer_received']and flows['archive_get_sent']==flows['validator_received']and flows['validator_sent']==flows['archive_get_received'],'actual endpoint application-byte conservation')
  result['actual_archive_put_get_overlap_intervals']=overlaps;result['archive_connection_peak']=max((row.get('counters',{}).get('connection_peak',0)for row in ar.rows),default=0)
  snap=result['deadline_snapshot'];drained=snap['scheduled_due_blocks']==snap['offered_blocks']==snap['accepted_blocks']==batches and not snap['due_but_not_materialized_ids'] and snap['reserved_or_unadmitted_credits']==0 and all(snap['counts'][state]==0 for state in STATES if state!='accepted')
  result['drained_at_fixed_deadline']=drained
  need(drained,'unfinished workload at fixed observation end');need(result['external_afterdeadline_canonical_equal'],'exact14 final source/destination equality');need(retained['bodies']==n*(batches+1)and retained['missing_full']==retained['pending']==retained['unexported_bytes']==retained['archive_committed_bytes']==0 and retained['cached_bytes']==retained['full_bytes']and retained['retention']==1,'all full retained bodies/no archive duty')
  need(len(native_totals)==2 and result['actual_stopped_to_restart_seconds']>=down,'two real native incarnations/downtime');laststates=[row['response']['result']['state']for row in applies if row['batch']in['ordinary2','ordinary'+str(batches)]];need(sum(row['proof_attempts']for row in laststates)==n*(batches+1)and sum(row['source_signature_attempts']for row in laststates)==n,'physical across-incarnation proof/signature attempts')
  need(overlaps and result['archive_connection_peak']==2,'actual bounded PUT/GET overlap');need(result['credit_backpressure_seconds_before_deadline']>0,'actual archive-credit backpressure')
  for path,old in prepared['stat_only_external_files'].items():
   st=Path(path).stat();need({'size':st.st_size,'blocks':st.st_blocks,'mtime_ns':st.st_mtime_ns,'inode':st.st_ino}==old,'external charged-copy stat drift')
  pins();buildpins();common.load_installation(a.installation.resolve(),a.approve_installation);need(sha(pp)==a.approve_profile and all(sha(p)==h for p,h in prepared['source_pins'].items()),'all source/runtime/public copies postcheck');result['passed']=True
 except BaseException as exc:
  fault_at=time.monotonic_ns();result['failure']={'type':type(exc).__name__,'message':str(exc),'observed_monotonic_ns':fault_at}
  if 'offers'in locals():
   result['interrupted_controller_snapshot']=offers.snapshot(min(fault_at,end));result['offer_events']=offers.events;result['role_events']=events;result['ordinary_ack_records_before_deadline']=applies
   if fault_at>=end and'deadline_snapshot'not in result:result['deadline_snapshot']=offers.snapshot(end)
  raise
 finally:
  for role in roles:
   receipt=role.cleanup()
   if receipt is not None and not any(x['pid']==receipt['pid']for x in receipts):receipts.append(receipt)
  u=resource.getrusage(resource.RUSAGE_SELF);result['controller_oracle_self_usage']={'user_seconds_delta':u.ru_utime-controller_usage.ru_utime,'system_seconds_delta':u.ru_stime-controller_usage.ru_stime,'peak_rss_kib_cumulative':u.ru_maxrss,'allowed_affinity':sorted(os.sched_getaffinity(0)),'wall_seconds':time.monotonic()-controller_start,'scope':'Separate experimental scheduler/preparation/metadata/oracle cost; SQL correctness checks run after measured observation end, not hidden inside validator service'}
  g1.save(work/'RESULT.json',{'format':'CP04-GATE2-PIPELINE-RESULT01','source_sha256':a.approve_source,'build_sha256':a.approve_build,'installation_sha256':a.approve_installation,'profile_sha256':a.approve_profile,'workload_sha256':a.approve_workload,'result':result,'roles':receipts,'scope':'Finite predeclared local full-duplex application-paced pipeline; no WAN/yearcapacity/PQ or pruned-participation conclusion; diagnostic2x3 is not96load'})
 print(json.dumps({'result':str(work/'RESULT.json'),'sha256':sha(work/'RESULT.json'),'passed':result['passed']}))
if __name__=='__main__':main()
