"""Small deterministic source controls; not valid-payment or throughput evidence."""
import sys
from pathlib import Path
sys.dont_write_bytecode=True
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from pipeline import Offers
objects={f'ordinary{i}':{'bytes':100+i}for i in range(1,4)}
o=Offers(objects,[0,0,.5],0);o.due(0);assert o.counts()['pending']==2
o.transition('ordinary1','uploading',1);o.transition('ordinary1','ready',2);o.transition('ordinary1','validating',3);o.transition('ordinary2','uploading',4);assert o.credits()==2
# A GET doesn't release credit. Only genuine canonical ACK transitions accepted.
o.due(500000000);assert o.counts()['pending']==1 and o.credits()==2
o.transition('ordinary1','accepted',500000001);assert o.credits()==1
o.transition('ordinary2','ready',500000002);o.transition('ordinary2','validating',500000003);o.transition('ordinary2','accepted',500000004)
# The retry is not an offered ordinary and has no state/credit transition.
before=o.snapshot(500000005);after=o.snapshot(500000006);assert before['counts']==after['counts']and before['reserved_or_unadmitted_credits']==after['reserved_or_unadmitted_credits']==0
o.transition('ordinary3','uploading',500000007);o.transition('ordinary3','ready',500000008);s=o.snapshot(500000009);assert s['accepted_blocks']==2 and s['counts']['ready']==1 and s['offered_blocks']==3
# Snapshot can't convert an incomplete batch into accepted or hide a missed offer.
p=Offers(objects,[0,0,.5],0);p.due(0);s=p.snapshot(500000000);assert s['scheduled_due_blocks']==3 and s['offered_blocks']==2 and s['due_but_not_materialized_ids']==['ordinary3']
try:o.transition('ordinary3','accepted',500000010)
except ValueError:pass
else:raise AssertionError('skipped validation accepted')
# A reaped uploader whose completion is first observed after cutoff remains
# unknown/uploading in the fixed-end controller state; its late ACK is separate.
clock=[9]
q=Offers(objects,[0,0,.5],0,10,lambda:clock[0]);q.due(0);q.transition('ordinary1','uploading',9);clock[0]=11
assert q.transition('ordinary1','ready',9)is False
s=q.snapshot(10);assert s['counts']['uploading']==1 and s['counts']['ready']==0 and s['late_transitions_not_counted'][0]['actual_controller_ns']==11
# Even a pre-end received event cannot silently launch/transition work when
# processing/reaping crossed cutoff; the event receipt stays in the late record.
clock[0]=9;r=Offers(objects,[0,0,.5],0,10,lambda:clock[0]);r.due(0);r.transition('ordinary1','uploading',9);r.transition('ordinary1','ready',9);r.transition('ordinary1','validating',9);r.transition('ordinary2','uploading',9);clock[0]=11
assert r.transition('ordinary2','ready',9)is False and r.credits()==2
print('{"scope":"deterministic public state/credit/deadline controls only","checks":9,"passed":true}')
