"""Privately link the sold tokens, received native coin and subsequent ordinary spend. Export counts and values."""
import argparse
from contextlib import ExitStack
import json
from pathlib import Path
import shutil
import struct
import sys
import tempfile

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
from swaps import ZERO, ast1, decode_pair, hash_bytes, joint
from wallet_joins import dbread, effects

REFERENCE_SHA = '360fa89587ec7dd6d349516ad26ccc29178c32e82f583568fc38c9520f59d8f5'
REFERENCE_KEY = '1895505caa69ce3cf55adcde8ce2e60c03ac0d7d4d8551888d71a8176e8b946d'


def restore(stack, home, deployment, actor):
    seed = home/'owner-backups'/actor/'seed'
    assert seed.is_file() and not seed.is_symlink() and not seed.stat().st_mode & 0o077 and seed.stat().st_size==32
    private = Path(stack.enter_context(tempfile.TemporaryDirectory()))
    shutil.copyfile(seed, private/'seed')
    (private/'seed').chmod(0o600)
    binary, keys = deployment/'runtime/native', deployment/'keys'
    approved=(deployment/'devnet/approved-native.sha256').read_text().strip()
    assert hash_bytes(binary.read_bytes()).hex() == approved
    assert hash_bytes((keys/'managed.vk').read_bytes()).hex() == REFERENCE_KEY
    role = ast1.Role(binary, approved, ['wallet','/keys','/private/seed','restore'], keys, private=private)
    stack.callback(role.abort)
    address = (home/'negotiation'/(actor+'.addr')).read_bytes()
    assert len(address) == 1673 and address[:8] == b'PQDADDR1' and hash_bytes(address[:-32]) == address[-32:]
    assert role.get() == address[40:-32]
    return role, address[40:-32]


def open_note(role, packet, index):
    cm = effects(packet)[1][index]
    start = len(packet)-3584+index*1792
    result = role.call(b'D'+cm+packet[start:start+1792])
    if result == b'MISS':
        return None
    assert len(result) == 84 and result[:3] == b'HIT' and result[3:35] != ZERO
    native, token, asset, kind = struct.unpack_from('<QQ32sB', result, 35)
    return result[3:35], native, token, asset, kind


def agreement(home, raw, owners, network, asset):
    assert len(raw) == 3361 and raw[:40] == b'SWPTER02'+network and raw[40:72] != ZERO
    assert raw[76] == 1
    offset = 77
    for expected_kind, address, give, amount in [(1,owners[0],asset,20), (0,owners[1],ZERO,8)]:
        group = raw[offset:offset+1642]
        assert group[0] == expected_kind and group[1:1602] == address and group[1602:1634] == give
        assert int.from_bytes(group[1634:], 'little') == amount
        offset += len(group)
    assert offset == len(raw) and owners[0] != owners[1]
    # Inspect the public tree for accidental export of the terms or any complete private address.
    for path in (home/'public').rglob('*'):
        if path.is_file():
            public = path.read_bytes()
            assert all(secret not in public for secret in (raw[40:72], *owners))
    return hash_bytes(b'SWP1/private-terms/v2\0'+raw)


def local(home, report):
    public, dep = home/'public', home/'deployment'
    run = json.loads((public/'RUN.json').read_bytes())
    summary = json.loads(report.read_bytes())
    signed = (public/'SWAP.bin').read_bytes()
    a,b = decode_pair(signed)
    assert hash_bytes(signed).hex() == summary['swap']['id']
    legs = (a[17195:], b[17195:])
    ids = [hash_bytes(f) for f in (a,b)]
    seller, buyer = 'alice', 'bob'
    asset = bytes.fromhex(run['asset_ids']['managed'])
    network = bytes.fromhex(summary['network'])
    spend_id = bytes.fromhex(run['ordinary']['respend-a']['tx'])
    spend = (public/'packets'/(spend_id.hex()+'.bin')).read_bytes()
    assert hash_bytes(spend) == spend_id and spend[:6] == b'MSP1\x01\x00'
    with ExitStack() as stack:
        roles, owners = zip(*(restore(stack,home,dep,actor) for actor in (seller,buyer)), strict=True)
        # Recover the privately signed terms, both journaled authorizations and their stable local source pins.
        raw = (home/'negotiation/accepted.terms').read_bytes()
        sealed = agreement(home,raw,owners,network,asset)
        assert a[43:75] == sealed == b[43:75]
        expiry, = struct.unpack_from('<I',raw,72)
        digest = joint(network,sealed,expiry,1,legs)
        pins = []
        for idx,(actor,frame) in enumerate(((seller,a),(buyer,b))):
            with dbread(home/'wallets'/actor/'mng1-intents.sqlite') as local_db:
                row, = local_db.execute('SELECT public,joint,signature,leg,state,pins FROM swap_sessions WHERE terms=? AND side=?',
                                        (sealed,idx)).fetchall()
            assert row[1:4] == (digest,frame[107:17195],legs[idx]) and row[4] in ('released','released-unlocked')
            assert row[0] == struct.pack('<8I', *struct.unpack_from('<8Q',legs[idx],len(legs[idx])-3584-64))
            source_pins = [bytes.fromhex(x) for x in json.loads(row[5])]
            assert len(source_pins)==1
            pins.append(source_pins[0])
        assert len(set(pins))==2
        # Reference software was released before native-for-token negotiation existed.
        token_in = open_note(roles[1],a,0)
        token_back = open_note(roles[0],a,1)
        native_in = open_note(roles[0],b,0)
        native_back = open_note(roles[1],b,1)
        assert token_in[1:] == (0,20,asset,2) and token_back[1:] == (0,80,asset,3)
        assert native_in[1:] == (8,0,ZERO,2) and native_back[2:] == (0,ZERO,3)
        assert open_note(roles[0],a,0) is None and open_note(roles[1],b,0) is None
        checks = []
        leg_key = dep/'swap-keys/swap.vk'
        leg_binary = dep/'swap-runtime/native'
        leg_sha = (dep/'devnet/approved-swap-native.sha256').read_text().strip()
        assert hash_bytes(leg_binary.read_bytes()).hex() == leg_sha
        assert hash_bytes(leg_key.read_bytes()).hex() == '0527447637fa2f34d9585606501c4a55883c0ceaf58adb2d3e9834c66ab19837'
        verifier = ast1.Role(leg_binary,leg_sha,['verify','/keys'],leg_key.parent)
        stack.callback(verifier.abort)
        for name,expected in [('short',(7,0,ZERO)),('substitute',(0,8,bytes.fromhex(run['asset_ids']['substitute'])))]:
            rejected = (home/'negotiation'/(name+'.leg')).read_bytes()
            observed=run['checks'][name]
            assert observed['genuine_proved_offer'] and not observed['final_signature_released'] and not observed['submitted']
            assert observed['error'].startswith('wallet cannot open') and not (home/'negotiation'/(name+'.sig')).exists()
            assert rejected[:5] == b'SLG1\x01' and rejected != legs[1]
            fx = verifier.call(rejected)
            assert len(fx) == 3789 and fx[0:1] == b'1' and int.from_bytes(fx[165:173],'little') == 3
            # Exactly one extracted receipt, from the real alternate proof, evaluated under Alice's backup.
            opened = roles[0].call(b'D'+fx[101:133]+fx[173:173+1792])
            assert opened[:3] == b'HIT' and len(opened) == 84 and opened[3:35] != ZERO
            assert struct.unpack_from('<QQ32sB',opened,35) == (*expected,2) and expected != (8,0,ZERO)
            with dbread(home/'wallets/bob-rival/mng1-intents.sqlite') as db:
                row, = db.execute('SELECT state,joint,signature FROM swap_sessions WHERE leg=?',(rejected,)).fetchall()
                assert row == ('aborted',None,None)
            checks.append(dict(candidate=name,previously_released_leg_verifier_accepted=True,
                               seller_backup_opened_payment=True,unsigned_offer_aborted=True))
        verifier.close()
        for role in roles:
            role.close()
    with dbread(home/'wallets/alice-restored/mng1-wallet-state.sqlite') as db:
        rows = db.execute('SELECT cm,nf,amount,asset,token,kind,creator FROM owned WHERE spender=?',(spend_id,)).fetchall()
        assert rows == [(effects(b)[1][0],native_in[0],8,ZERO,0,'incoming',ids[1])]
        assert native_in[0] in effects(spend)[0]
        got = db.execute('SELECT cm,amount,asset,token FROM owned WHERE spender=?',(ids[0],)).fetchall()
        assert got == [(pins[0],0,asset,100)]
        remaining = db.execute('SELECT cm,amount,asset,token FROM owned WHERE spent IS NULL AND (amount>0 OR token>0)').fetchall()
        assert remaining == [(effects(a)[1][1],0,asset,80)]
    with dbread(home/'wallets/bob/mng1-wallet-state.sqlite') as db:
        got = db.execute('SELECT cm,amount,asset,token FROM owned WHERE spender=?',(ids[1],)).fetchall()
        assert got == [(pins[1],native_back[1]+11,ZERO,0)]
    with dbread(home/'wallets/forward/mng1-wallet-state.sqlite') as db:
        row, = db.execute('SELECT amount,token,asset,kind,creator FROM owned WHERE cm=?',(effects(spend)[1][0],)).fetchall()
        assert row == (5,0,ZERO,'incoming',spend_id)
    with dbread(home/'wallets/alice-restored/mng1-intents.sqlite') as db:
        row, = db.execute("SELECT accounting FROM attempts WHERE intent='respend-a' AND tx=?",(spend_id.hex(),)).fetchall()
        amounts = json.loads(row[0])
        frozen, = db.execute("SELECT pinned FROM intents WHERE id='respend-a'").fetchone()
        assert json.loads(frozen) == [effects(b)[1][0].hex()]
        assert (amounts['input_total'],amounts['real_inputs'],amounts['amount'],amounts['fee'],amounts['change'],
                amounts['token_amount'],amounts['token_change']) == (8,1,5,3,0,0,0)
    return dict(reference_ordinary_wallet_recovered_seeds=2,verified_spendable_ordered_swap_outputs=4,
                wrong_owner_misses=2,independent_local_agreements_and_signatures=2,alternate_offers=checks,swap_input_count_each=[1,1],
                seller_initial=dict(token=100,native=0),seller_swap_change=dict(token=80,native=0),
                buyer_native_change=native_back[1],seller_incoming_native=8,ordinary_real_inputs=1,
                ordinary_consumed_exact_acquired_native_output=True,ordinary_payment=5,ordinary_fee=3,
                seller_selected_final=dict(token=80,native=0),historical_managed_verifier_key=REFERENCE_KEY,
                historical_managed_x86_64_binary_matched=hash_bytes((dep/'runtime/native').read_bytes()).hex()==REFERENCE_SHA)


if __name__ == '__main__':
    if not __debug__:
        sys.exit('enable assertions')
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('home',type=Path); parser.add_argument('public_audit',type=Path)
    args=parser.parse_args()
    print(json.dumps(local(args.home,args.public_audit),indent=2,sort_keys=True))
