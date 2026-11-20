"""Independently bind private firm quotes, wallets, real funding notes and signing journals to the public pair."""
import argparse
from base64 import b64encode
from contextlib import ExitStack
from hashlib import sha256
import json
from pathlib import Path
import struct
import sys

HERE=Path(__file__).resolve().parent
sys.path.insert(0,str(HERE))
from adverts import FIELDS,NETWORK,canonical
from wallet import ast1,decode_pair,dbread,restore_role

ZERO=bytes(32)
QFIELDS={'version','advert','request','holder','quote','network','maker','taker','asset','quantity','native','payer',
         'fee','expiry_height','expires','nonce'}
REQ={'op','advert','request','cap','taker','asset','quantity'}


def word(value,size=32):
    data=bytes.fromhex(value)
    assert len(data)==size and data.hex()==value
    return data


def private_terms(q,request,ad):
    assert set(q)==QFIELDS and set(ad)==FIELDS and set(request)==REQ
    assert q['advert']==request['advert']==sha256(canonical(ad)).hexdigest()
    assert q['network']==ad['network']==NETWORK and q['request']==request['request'] and request['op']=='quote'
    assert q['holder']==sha256(word(request['cap'])).hexdigest() and q['taker']==request['taker']!=q['maker']
    assert q['payer']=='b' and q['fee']==3 and q['version']==1
    assert q['quantity']==request['quantity']==20 and q['native'] in (7,8)
    assert q['asset']==request['asset'] and word(q['asset'])!=ZERO
    assert 0<q['expiry_height']<2**32 and ad['issued']<=q['expires']<=ad['expires']
    assert len({word(q[k]) for k in ('nonce','request','holder','quote')})==4
    blind=sha256(b'SSW1/firm-quote/v1\0'+canonical(q)).digest()
    terms=b'SWPTER02'+word(q['network'])+blind+struct.pack('<IB',q['expiry_height'],1)
    terms+=b'\x01'+word(q['taker'],1601)+word(q['asset'])+struct.pack('<Q',q['quantity'])
    terms+=b'\x00'+word(q['maker'],1601)+ZERO+struct.pack('<Q',q['native'])
    assert len(terms)==3361
    return terms,sha256(b'SWP1/private-terms/v2\0'+terms).digest()


def check(home,swap,seller_backup,adverts):
    raw=swap.read_bytes();frames=decode_pair(raw);selected_terms=frames[0][43:75]
    inputs={};makers={};matched=[];n_quotes=0; signatures=0;private_values=[];actual={}
    taker=home/'participants/taker'; deployment=home/'deployment'
    ad_rows=[json.loads(x.read_bytes()) for x in adverts];ad_ids={sha256(canonical(v)).hexdigest() for v in ad_rows}
    assert len(ad_ids)==2
    with ExitStack() as stack:
        a,a_address=restore_role(stack,seller_backup,deployment)
        key=deployment/'swap-keys/swap.vk';program=deployment/'swap-runtime/native'
        approved=(deployment/'devnet/approved-swap-native.sha256').read_text().strip()
        assert sha256(key.read_bytes()).hexdigest()=='0527447637fa2f34d9585606501c4a55883c0ceaf58adb2d3e9834c66ab19837'
        verifier=ast1.Role(program,approved,['verify','/keys'],key.parent);stack.callback(verifier.abort)
        for state_file in sorted((taker/'stranger-private/alice/taker').glob('*/session.json')):
            folder=state_file.parent;st=json.loads(state_file.read_bytes())
            if 'firm' not in st:
                continue
            q,req,ad=st['firm'],st['req'],st['ad']
            assert q['advert'] in ad_ids and q['request']==folder.name and bytes.fromhex(q['taker'])==a_address
            terms,commit=private_terms(q,req,ad)
            actual[q['native']]=(q,req,ad)
            assert terms==(folder/'terms').read_bytes()
            peer_home,alias=('maker','maker') if q['native']==8 else ('other','other')
            peer=home/'participants'/peer_home;mf=peer/'stranger-private'/alias/'maker'/q['request']
            if alias not in makers:
                maker_role,addr=restore_role(stack,peer/'wallets'/alias/'seed',deployment)
                makers[alias]=(maker_role,addr)
            maker_role,addr=makers[alias]
            assert addr==word(q['maker'],1601) and addr!=a_address
            mst=json.loads((mf/'session.json').read_bytes())
            assert mst['firm']==q and mst['req']==req and mst['ad']==ad and (mf/'terms').read_bytes()==terms
            leg=(mf/'leg-b').read_bytes()
            assert (folder/'leg-b').read_bytes()==leg and leg[:5]==b'SLG1\x01'
            effect=verifier.call(leg)
            assert len(effect)==3789 and effect[:1]==b'1' and int.from_bytes(effect[165:173],'little')==3
            opened=a.call(b'D'+effect[101:133]+effect[173:1965])
            assert len(opened)==84 and opened[:3]==b'HIT' and opened[3:35]!=ZERO
            assert struct.unpack_from('<QQ32sB',opened,35)==(q['native'],0,ZERO,2)
            tag=q['advert']
            with dbread(peer/'wallets'/alias/'mng1-intents.sqlite') as box:
                row,=box.execute('SELECT leg,pins,joint,signature,state FROM swap_sessions WHERE terms=? AND side=1',(commit,)).fetchall()
                assert row[0]==leg
                pins=json.loads(row[1]);assert len(pins)==1
                did_sign=row[3] is not None
            with dbread(peer/'wallets'/alias/'mng1-wallet-state.sqlite') as owned:
                src,=owned.execute('SELECT amount,asset,token,nf,origin FROM owned WHERE cm=?',(word(pins[0]),)).fetchall()
                assert src[0]>=q['native']+3 and src[1:3]==(ZERO,0) and src[3] in (effect[37:69],effect[69:101])
                source=maker_role.call(b'D'+src[4])
                assert source[:3]==b'HIT' and source[3:35]==src[3] and struct.unpack_from('<QQ32s',source,35)==(src[0],0,ZERO)
            inputs.setdefault(tag,set()).add(pins[0]);n_quotes+=1
            if commit==selected_terms:
                assert did_sign and q['native']==8 and frames[1][17195:]==leg
                assert frames[0][17195:]==(folder/'leg-a').read_bytes()
                assert row[3]==frames[1][107:17195] and (folder/'sig-a').read_bytes()==frames[0][107:17195]
                assert (folder/'packet').read_bytes()==raw
                signatures+=1
            else:
                assert not did_sign and not (folder/'sig-a').exists() and not (mf/'sig-b').exists()
            private_values.extend([terms,word(req['cap']),word(q['nonce']),word(q['quote']),word(q['request']),
                                   word(q['maker'],1601),a_address,leg])
            matched.append(dict(price_native=q['native'],offered_tokens=q['quantity'],actual_funded_input_count=len(pins),
                                privately_opened_correct_native_output=True,selected=commit==selected_terms,
                                maker_final_state=mst['state'],taker_final_state=st['state'],maker_signed=did_sign))
        assert len({v[1] for v in makers.values()})==2
        for role,addr in makers.values():
            role.close()
        verifier.close();a.close()
    assert n_quotes==3 and set(inputs)==ad_ids and signatures==1
    assert sorted((r['price_native'],r['taker_final_state'],r['maker_signed']) for r in matched)==[
        (7,'cancelled',False),(7,'cancelled',False),(8,'complete',True)]
    # Supply the other funded maker's actual firm across each live quote's original request.
    # Exercise the shipped verifier on copies, before any monetary operation.
    sys.path.insert(0,str(HERE.parent))
    from negotiation import quote_terms
    cross_denials=0
    for price,other in ((7,8),(8,7)):
        q,req,ad=actual[price]
        assert quote_terms(q,ad,req).encode()==private_terms(q,req,ad)[0]
        try:
            quote_terms(actual[other][0],ad,req)
        except ValueError:
            cross_denials+=1
    assert cross_denials==2
    first,second=inputs.values()
    assert first.isdisjoint(second) and {r['price_native'] for r in matched}=={7,8}
    # Check the actual published advert encodings. Fixed schema and parsing give the strongest field-level test.
    for ad in ad_rows:
        encoded=canonical(ad)
        assert all(x not in encoded and x.hex().encode() not in encoded and b64encode(x) not in encoded
                   for x in private_values)
    return dict(authenticated_local_firm_quote_count=n_quotes,distinct_funded_makers=2,
                all_MLDSA_service_identities_matched=True,distinct_native_source_notes_across_makers=True,
                crossed_real_firm_quotes_rejected_by_wallet=cross_denials,
                recomputed_terms_and_matched_selected_signature_pair=True,consenting_seller_seed_opened_each_native_offer=True,
                no_full_quote_capability_nonce_private_address_or_leg_in_advert=True,checks=matched)


if __name__=='__main__':
    if not __debug__:sys.exit('enable assertions')
    p=argparse.ArgumentParser(description=__doc__)
    for n in ('home','swap','seller_backup'):
        p.add_argument(n,type=Path)
    p.add_argument('adverts',type=Path,nargs=2)
    a=p.parse_args();print(json.dumps(check(a.home,a.swap,a.seller_backup,a.adverts),indent=2,sort_keys=True))
