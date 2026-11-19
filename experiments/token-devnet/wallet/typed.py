"""The two amounts are ordered (native, registered token); only native pays fees."""
import hashlib
from itertools import combinations
import struct

MAX=(1<<62)-1
FEE=3

def check_pair(amount):
    if (not isinstance(amount,(tuple,list)) or len(amount)!=2 or
        not all(type(x) is int and 0<=x<=MAX for x in amount) or not any(amount)):
        raise ValueError("supply native and token amounts in the 62-bit range, at least one positive")
    return tuple(amount)

def default_id(address,amount):
    return "pay-"+hashlib.sha256(b"TKN1/devnet/local-intent/v1\0"+address+struct.pack("<QQ",*check_pair(amount))).hexdigest()[:32]

def select_amounts(rows,amount,exclude):
    native,token=check_pair(amount)
    eligible=[(cm.hex(),n,t) for cm,n,t in rows if not exclude(cm.hex())]
    # Try singletons then pairs in stable public-leaf position order. A valid result must leave
    # bounded change on each lane. No fee value or token-bearing output is silently discarded.
    for width in (1,2):
        for group in combinations(eligible,width):
            n=sum(row[1] for row in group)-native-FEE
            t=sum(row[2] for row in group)-token
            if 0<=n<=MAX and 0<=t<=MAX:
                return tuple(row[0] for row in group)
    raise ValueError("insufficient funds within two unreserved inputs")

class TypedWallet:
    def open_row(self,row):
        if len(row) not in (112,1824):
            raise ValueError("invalid typed note source")
        b=self.role.call(b"D"+row)
        if b==b"MISS":
            return None
        if len(b)!=52 or b[:3]!=b"HIT" or b[-1] not in (1,2,3):
            raise ValueError("invalid typed note opening")
        native,token=struct.unpack_from("<QQ",b,35)
        return b[3:35],native,token,("reward","incoming","change")[b[-1]-1]

    def compact_payment(self,header,amount,to,sources):
        n,t=check_pair(amount)
        if len(header)!=132 or len(to)!=1601 or len(sources) not in (1,2):
            raise ValueError("invalid typed payment request")
        data=bytearray(b"K"+header+struct.pack("<QQ",n,t)+to+bytes([len(sources)]))
        for row,levels in sources:
            if len(row) not in (112,1824) or not 1<=len(levels)<=20:
                raise ValueError("invalid typed membership source")
            data.extend(struct.pack("<HB",len(row),len(levels))+row)
            for level in levels:
                if len(level)!=3 or any(len(s)!=32 for s in level):
                    raise ValueError("invalid private membership")
                data.extend(b"".join(level))
        raw=self.role.call(bytes(data))
        if raw[:5]!=b"TKN1\x01" or len(raw)!=9+int.from_bytes(raw[5:9],"little")+3584:
            raise ValueError("typed prover refused the payment")
        return raw

class TypedState:
    def initialize_founder(self):
        import chain
        from wallet_sync import Tree, EMPTY_BALANCE, flatten, tally
        row=chain.FOUNDING_ROW
        cm=row[-32:]
        if len(row)!=112 or struct.unpack("<QQ",row[64:80])!=(0,240):
            raise ValueError("wrong approved founder allocation")
        tree=Tree(0,b"",self.combine)
        groups,root=tree.append(cm)
        if root!=chain.GENESIS_HEADER[-32:]:
            raise ValueError("wrong approved funded root")
        hit=self.wallet.open_row(row)
        balance=EMPTY_BALANCE.copy()
        if hit is not None:
            nf,n,t,_=hit
            path=[children[:slot]+children[slot+1:] for slot,children in groups]
            self.db.execute("INSERT INTO owned VALUES(?,?,?,?,?,?,?,?,?,NULL,NULL,?)",
                            (cm,nf,0,n,t,"founding",row,0,None,flatten(path)))
            tally(balance,"founding",n,t,1)
        import json
        self.db.execute("UPDATE heads SET n=1,front=?,balance=? WHERE h=0",(tree.encode(),json.dumps(balance)))

    def select(self,amount,exclude=()):
        blocked=exclude if callable(exclude) else set(exclude).__contains__
        rows=self.db.execute("SELECT cm,amount,token FROM owned WHERE spent IS NULL AND (amount>0 OR token>0) ORDER BY pos")
        return select_amounts(rows,amount,blocked)

    def pay(self,amount,to,pinned):
        from wallet_sync import path_rows
        native,token=check_pair(amount)
        if len(pinned) not in (1,2) or len(set(pinned))!=len(pinned):
            raise ValueError("invalid pinned real inputs")
        self.last_payment=None
        with self.transaction(False):
            header=self.header
            notes=[]
            nt=tt=0
            nfs=[]
            for cm in pinned:
                row=self.db.execute("SELECT origin,amount,token,nf,path FROM owned WHERE cm=? AND spent IS NULL AND (amount>0 OR token>0)",
                                    (bytes.fromhex(cm),)).fetchone()
                if row is None:
                    raise ValueError("pinned input unavailable on selected branch")
                nt+=row["amount"]
                tt+=row["token"]
                nfs.append(row["nf"].hex())
                notes.append((row["origin"],path_rows(row["path"])))
        if not (0<=nt-native-FEE<=MAX and 0<=tt-token<=MAX):
            raise ValueError("insufficient pinned amounts")
        packet=self.wallet.compact_payment(header,(native,token),to,notes)
        self.last_payment=dict(amount=native,token_amount=token,fee=FEE,input_total=nt,token_input_total=tt,
                               change=nt-native-FEE,token_change=tt-token,real_inputs=len(pinned),
                               input_commitments=list(pinned),real_nullifiers=nfs)
        self.wallet.last_payment=self.last_payment
        return packet

def tally(balance,kind,n,t,sign):
    if not (n or t):
        return
    balance["balance"]+=sign*n
    balance["token_balance"]+=sign*t
    balance["notes"]+=sign
    balance[kind+"_notes"]+=sign
    if kind in ("incoming","change"):
        balance["receipt_notes"]+=sign
