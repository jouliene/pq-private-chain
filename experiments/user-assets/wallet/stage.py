"""Install the AST1 wallet into a deployment staged from the ordinary devnet sources."""
from pathlib import Path
import shutil

HERE = Path(__file__).resolve().parent


def once(source, old, new):
    if source.count(old) != 1:
        raise ValueError("AST1 wallet stage expected one match for " + old[:80])
    return source.replace(old, new)


def section(source, start, end, replacement=""):
    left = source.index(start)
    right = source.index(end, left)
    return source[:left] + replacement + source[right:]


def wallet(source):
    source = section(source, "def checked_keys(", "def private_directory(", "from runtime import checked_keys\n\n\n")
    source = once(source, "class Wallet:", "from asset_wallet import AssetWallet\n\n\nclass Wallet(AssetWallet):")
    return section(source, "    def scan(", "    def close(")


def cursor(source):
    source = section(source, "def tally(", "def role_sample(")
    source = section(source, "    def select(", "    def add_count(")
    source = once(source, "class WalletSync:", "from asset_wallet import AssetState, tally\n\n\nclass WalletSync(AssetState):")
    source = source.replace('ZERO+chain.u32(0)+chain.digest(b"dev-genesis-state",chain.NETWORK)+chain.digest(b"dev-genesis-body",chain.NETWORK)+ZERO',
                            "chain.GENESIS_HEADER")
    source = once(source, "EMPTY_BALANCE=dict(balance=0,", "EMPTY_BALANCE=dict(balance=0,assets={},")
    source = once(source, '"wallet-state.sqlite"', '"ast1-wallet-state.sqlite"')
    source = once(source, "amount INTEGER,kind TEXT", "amount INTEGER,asset BLOB NOT NULL,token INTEGER NOT NULL,kind TEXT")
    source = source.replace("spent IS NULL AND amount>0", "spent IS NULL AND (amount>0 OR token>0)")
    source = once(source, 'amount=row["amount"],source=', 'amount=row["amount"],asset_id=row["asset"].hex(),token_amount=row["token"],source=')
    source = once(source, "SELECT cm,amount,kind,spent", "SELECT cm,amount,asset,token,kind,spent")
    source = once(source, "nf,amount,kind=hit", "nf,amount,asset,token,kind=hit")
    source = once(source, "VALUES(?,?,?,?,?,?,?,?,NULL,NULL,?)", "VALUES(?,?,?,?,?,?,?,?,?,?,NULL,NULL,?)")
    source = once(source, "(cm,nf,i,amount,kind,row,h,tx,flatten(siblings) if amount else None)",
                  "(cm,nf,i,amount,asset,token,kind,row,h,tx,flatten(siblings) if amount or token else None)")
    source = once(source, "if amount:", "if amount or token:")
    source = once(source, "tally(balance,kind,amount,1)", "tally(balance,kind,amount,asset,token,1)")
    source = once(source, "SELECT cm,kind,amount,spent", "SELECT cm,kind,amount,asset,token,spent")
    source = once(source, 'tally(balance,known["kind"],known["amount"],-1)',
                  'tally(balance,known["kind"],known["amount"],known["asset"],known["token"],-1)')
    source = once(source, "add(reward,reward[-32:],None)", "add(reward[:72]+bytes(8)+reward[72:],reward[-32:],None)")
    return once(source, 'transitions.append(b"".join((*nfs,*cms,chain.u64(FEE))))',
                'transitions.append(chain.public_transition(nfs,cms,FEE,slot["issue_id"],slot["supply"]))')


def journal(source):
    source = section(source, "def default_id(", "class Outbox:",
                     "from asset_wallet import Request, default_id, check_accounting\n\n\n")
    source = once(source, '"intents.sqlite"', '"ast1-intents.sqlite"')
    source = once(source, "amount INTEGER NOT NULL,", "amount INTEGER NOT NULL, asset BLOB NOT NULL, token INTEGER NOT NULL, supply INTEGER NOT NULL,")
    source = section(source, "    def register(", "    def attempts(", '''    def register(self,ident,address,request):
        if not isinstance(request,Request) or len(address)!=1601:
            raise ValueError("invalid AST1 intent")
        with self.db:
            self.db.execute("INSERT OR IGNORE INTO intents(id,address,amount,asset,token,supply) VALUES(?,?,?,?,?,?)",
                            (identifier(ident),address,request.native,request.asset,request.token,request.supply))
        row=self.get(ident)
        if row["address"]!=address or Request.from_row(row)!=request:
            raise ValueError("intent already binds a different recipient, asset, issuance or amount")

''')
    source = section(source, "        account={k:payment[k]", "        # The private prover", '''        intent=self.get(ident)
        account=check_accounting(payment,intent,cms,state.network)
        account["encoded_bytes"]=len(raw)
''')
    source = section(source, "    def summary(", "    def drive(", '''    def summary(self,ident):
        intent=self.get(ident)
        newest=self.db.execute("SELECT accounting FROM attempts WHERE intent=? ORDER BY rowid DESC LIMIT 1",
                               (ident,)).fetchone()
        resolved=json.loads(newest[0])["asset_id"] if newest else None
        return dict(intent=ident,amount=intent["amount"],token_amount=intent["token"],
                    requested_asset=intent["asset"].hex(),asset_id=resolved,issue_supply=intent["supply"],
                    last_observed=intent["disposition"],attempts=[a["tx"] for a in self.attempts(ident)])

''')
    source = once(source, 'state.select(row["amount"],', 'state.select(Request.from_row(row),')
    return once(source, 'state.pay(row["amount"],', 'state.pay(Request.from_row(row),')


def cli(source):
    source = section(source, "    def send(", "    def resume(", '''    def send(self,name,to,native,asset_id,token,node,intent=None,wait_seconds=0):
        from asset_wallet import Request, default_id, parse_asset
        request=Request(native,parse_asset(asset_id),token)
        address=self.destination(to)
        return self._outgoing(name,node,intent or default_id(address,request),wait_seconds,address,request)

    def issue(self,name,supply,node,intent=None,wait_seconds=0):
        from asset_wallet import Request, default_id
        request=Request.issue(supply)
        address=self.address(name)
        return self._outgoing(name,node,intent or default_id(address,request),wait_seconds,address,request)

''')
    source = once(source, 'c.add_argument("recipient");c.add_argument("amount",type=int);',
                  'c.add_argument("recipient");c.add_argument("native",type=int);c.add_argument("asset_id");c.add_argument("token",type=int);')
    source = once(source, '    c=subs.add_parser("send");', '''    c=subs.add_parser("issue");c.add_argument("sender");c.add_argument("supply",type=int);c.add_argument("--intent");c.add_argument("--wait",type=int,default=0);c.add_argument("--node",choices=NODES,default="c")
    c=subs.add_parser("send");''')
    source = once(source, '    elif args.op=="send":', '''    elif args.op=="issue":
        result=lab.issue(args.sender,args.supply,args.node,args.intent,args.wait)
    elif args.op=="send":''')
    return once(source, "args.recipient,args.amount,args.node", "args.recipient,args.native,args.asset_id,args.token,args.node")


def stage_wallet(dev):
    dev = Path(dev)
    shutil.copyfile(HERE / "asset_wallet.py", dev / "asset_wallet.py")
    for name, specialize in (("wallet", wallet), ("wallet_sync", cursor), ("intents", journal), ("cli", cli)):
        path = dev / (name + ".py")
        source = specialize(path.read_text())
        compile(source, path, "exec")
        path.write_text(source)
