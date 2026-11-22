"""Prove that the published public fixture reproduces with no original wallet or database."""
from contextlib import ExitStack
import json
from pathlib import Path
import subprocess
import sys
import tempfile

HERE=Path(__file__).resolve().parent
sys.path.insert(0,str(HERE))
from campaign import checked, fails, need, public_view
from roles import Role
from stage import install


def run(out,ports,stack):
    fixture=out/'fixture'
    case=json.loads((fixture/'case.json').read_bytes())
    # Operator trust input comes from the checked-out project, separate from the fixture peer's files.
    registry=json.loads((HERE/'FIXTURE.json').read_bytes())
    pin=out/'expected.json'
    pin.write_text(json.dumps(registry['pin']))
    dep=install(out/'source/deployment',out/'registered')
    def launch(name,**kw):
        role=Role(dep,ports,name,out/'stores'/name,**kw)
        stack.callback(role.stop)
        return role
    peer=launch('peer',fixture=fixture)
    snap=launch('snap',source=peer.public,pin=pin)
    ordinary=launch('ordinary',source=peer.public)
    target=case['main'][-1]
    checked(snap,'bootstrap',target=target)
    checked(ordinary,'advance',start=1,target=target)
    need(public_view(snap)==public_view(ordinary),'fixed selected monetary state')
    # An unavailable losing base must not veto a heavier branch that can be validated in full.
    peer.rpc('fault',fault={'op':'block','id':case['base'],'mode':'gap'})
    miss=fails(snap,'verify','unavailable',target=case['base'])
    need(miss['status']['bootstrap']['historical_status']=='historical prefix assumed','premature promotion')
    wanted=case['fork'][-1]
    adopted=checked(snap,'fork',target=wanted)
    need(adopted['status']['bootstrap']['mode']=='full','preferred fork replay')
    checked(ordinary,'advance',start=case['base_height'],target=wanted)
    result=public_view(snap)
    need(result==public_view(ordinary),'fixed fork state')
    print(json.dumps({'fully_replayed_tip':result['tip'],'spent':result['spent'],'fees':result['fees'],
                      'winning_branch_verified_with_losing_base_offline':True}))
    for role in (snap,ordinary):
        role.stop()
    subprocess.run([sys.executable,'-IB',HERE/'review/check.py',fixture,snap.store/'live.sqlite',
                    ordinary.store/'live.sqlite','--pin',pin],check=True)


if __name__=='__main__':
    with tempfile.TemporaryDirectory(prefix='snb-fixed-') as tmp, ExitStack() as stack:
        run(Path(sys.argv[1]).resolve(),Path(tmp),stack)
