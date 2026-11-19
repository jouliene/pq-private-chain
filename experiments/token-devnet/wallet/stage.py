"""Specialize the existing ordinary wallet, atomic cursor and sender journal for the TKN1 chain."""
from pathlib import Path
import shutil

HERE=Path(__file__).resolve().parent

def once(source,old,new):
    if source.count(old)!=1:
        raise ValueError("wallet stage requires unique input: "+old[:96])
    return source.replace(old,new)

def cut(s,begin,end):
    return s[:s.index(begin)]+s[s.index(end,s.index(begin)):]

def stage_wallet(dev):
    dev=Path(dev)
    shutil.copy2(HERE/"typed.py",dev/"typed.py")
    p=dev/"wallet.py"
    s=p.read_text()
    s=cut(s,"def checked_keys(","def private_directory(")
    s=once(s,"class Wallet:","from typed import TypedWallet\nfrom runtime import checked_keys\n\nclass Wallet(TypedWallet):")
    s=cut(s,"    def scan(","    def close(")
    p.write_text(s)

    p=dev/"wallet_sync.py"
    s=p.read_text()
    s=cut(s,"def tally(","def role_sample(")
    s=cut(s,"    def select(","    def add_count(")
    s=once(s,"class WalletSync:","from typed import TypedState, tally\n\nclass WalletSync(TypedState):")
    s=s.replace('ZERO+chain.u32(0)+chain.digest(b"dev-genesis-state",chain.NETWORK)+chain.digest(b"dev-genesis-body",chain.NETWORK)+ZERO','chain.GENESIS_HEADER')
    s=once(s,"EMPTY_BALANCE=dict(balance=0,","EMPTY_BALANCE=dict(balance=0,token_balance=0,founding_notes=0,")
    s=once(s,'self.path=self.directory/"wallet-state.sqlite"','self.path=self.directory/"typed-wallet-state.sqlite"')
    s=once(s,"amount INTEGER,kind TEXT","amount INTEGER,token INTEGER,kind TEXT")
    s=s.replace("spent IS NULL AND amount>0","spent IS NULL AND (amount>0 OR token>0)")
    s=once(s,'self.hashes.times=deque(maxlen=1)','''self.hashes.times=deque(maxlen=1)
            self.stats=None
            with self.transaction():
                if self.db.execute("SELECT n FROM heads WHERE h=0").fetchone()[0]==0:
                    self.initialize_founder()''')
    s=once(s,'self.add_count("deep_resets")','self.initialize_founder()\n                self.add_count("deep_resets")')
    s=once(s,"height<=n<=CAPACITY","height+1<=n<=CAPACITY")
    s=once(s,'amount=row["amount"],source=','amount=row["amount"],token_amount=row["token"],source=')
    s=once(s,"SELECT cm,amount,kind,spent FROM owned","SELECT cm,amount,token,kind,spent FROM owned")
    s=once(s,"nf,amount,kind=hit","nf,amount,token,kind=hit")
    s=once(s,"VALUES(?,?,?,?,?,?,?,?,NULL,NULL,?)","VALUES(?,?,?,?,?,?,?,?,?,NULL,NULL,?)")
    s=once(s,"(cm,nf,i,amount,kind,row,h,tx,flatten(siblings) if amount else None)","(cm,nf,i,amount,token,kind,row,h,tx,flatten(siblings) if amount or token else None)")
    s=once(s,"if amount:","if amount or token:")
    s=once(s,"tally(balance,kind,amount,1)","tally(balance,kind,amount,token,1)")
    s=once(s,"SELECT cm,kind,amount,spent","SELECT cm,kind,amount,token,spent")
    s=once(s,'tally(balance,known["kind"],known["amount"],-1)','tally(balance,known["kind"],known["amount"],known["token"],-1)')
    s=once(s,'add(reward,reward[-32:],None)','add(reward[:72]+bytes(8)+reward[72:],reward[-32:],None)')
    p.write_text(s)

    p=dev/"intents.py"
    s=p.read_text()
    s=cut(s,"def default_id(","class Outbox:")
    s=once(s,"class Outbox:","from typed import check_pair,default_id\n\nclass Outbox:")
    s=once(s,'/"intents.sqlite"','/"typed-intents.sqlite"')
    s=once(s,"amount INTEGER NOT NULL","amount INTEGER NOT NULL, token INTEGER NOT NULL")
    s=once(s,"if type(amount) is not int or not 0<amount<=MAX_VALUE or len(address)!=1601:","native,token=check_pair(amount)\n        if len(address)!=1601:")
    s=once(s,"intents(id,address,amount) VALUES(?,?,?)","intents(id,address,amount,token) VALUES(?,?,?,?)")
    s=once(s,"(identifier(ident),address,amount))","(identifier(ident),address,native,token))")
    s=once(s,'r["amount"]!=amount','(r["amount"],r["token"])!=(native,token)')
    s=once(s,'("amount","fee","change","input_total","real_inputs")','("amount","token_amount","fee","change","token_change","input_total","token_input_total","real_inputs")')
    s=once(s,'account["amount"]!=intent["amount"] or','account["amount"]!=intent["amount"] or\n                account["token_amount"]!=intent["token"] or account["token_change"]<0 or\n                account["token_input_total"]!=account["token_amount"]+account["token_change"] or')
    s=once(s,'amount=r["amount"],last_observed','amount=r["amount"],token_amount=r["token"],last_observed')
    s=once(s,'state.select(row["amount"],','state.select((row["amount"],row["token"]),')
    s=once(s,'state.pay(row["amount"],','state.pay((row["amount"],row["token"]),')
    p.write_text(s)

    p=dev/"cli.py"
    s=p.read_text()
    s=once(s,"def send(self,name,to,amount,node,intent=None,wait_seconds=0):","def send(self,name,to,native,token,node,intent=None,wait_seconds=0):\n        amount=(native,token)")
    s=once(s,'c.add_argument("recipient");c.add_argument("amount",type=int);','c.add_argument("recipient");c.add_argument("native",type=int);c.add_argument("token",type=int);')
    s=once(s,"args.recipient,args.amount,args.node","args.recipient,args.native,args.token,args.node")
    p.write_text(s)
