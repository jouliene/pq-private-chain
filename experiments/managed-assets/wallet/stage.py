"""Specialize an already staged AST1 client for the managed registration and signed supply events."""
from pathlib import Path
import shutil

HERE = Path(__file__).resolve().parent
AST = HERE.parents[1] / "user-assets"


def once(source, old, new):
    if source.count(old) != 1:
        raise ValueError("managed wallet stage expected a single match near " + repr(old[:72]))
    return source.replace(old, new)


def replace_section(source, first, after, body):
    start = source.index(first)
    end = source.index(after, start)
    return source[:start] + body + source[end:]


def asset_wallet(source):
    source = replace_section(source, "@dataclass", "def select_amounts(", "")
    source = once(source, "    eligible = ", "    from managed_wallet import permitted, change_for\n    eligible = ")
    source = once(source, 'b"AST1\\x01"', 'b"MNG1\\x01"')
    source = once(source, "        rows = self.db.execute(", """        if request.burn:
            from managed_wallet import change_for, select_return
            return select_return(self.db, request, blocked, change_for)
        rows = self.db.execute(""")
    source = once(source, "        from wallet_sync import path_rows, role_sample",
                  "        from wallet_sync import path_rows, role_sample\n"
                  "        from managed_wallet import permitted, change_for, authorize, validate_return, envelope")
    source = once(source, "            header = self.header", """            header = self.header
            if request.burn:
                validate_return(self, request, pinned)""")
    source = replace_section(source, "        if request.supply:", "        before = role_sample",
                             "        resolved, public = authorize(self.wallet, self.network, request, nfs, asset_ids)\n")
    source = once(source, "        self.wallet.last_payment = self.last_payment", """        packet = envelope(self.wallet, self.network, request, packet, public)
        self.last_payment["issuer_key"] = public.hex()
        self.wallet.last_payment = self.last_payment""")
    return source[:source.index("def check_accounting(")]


def journal(source):
    source = once(source, "from asset_wallet import Request, default_id, check_accounting",
                  "from managed_wallet import Request, default_id, check_accounting")
    source = once(source, '"ast1-intents.sqlite"', '"mng1-intents.sqlite"')
    source = once(source, "supply INTEGER NOT NULL,", "supply INTEGER NOT NULL, operation TEXT NOT NULL, "
                  "return_tx BLOB NOT NULL, sequence INTEGER NOT NULL, previous BLOB NOT NULL,")
    source = once(source, "asset,token,supply) VALUES(?,?,?,?,?,?)",
                  "asset,token,supply,operation,return_tx,sequence,previous) VALUES(?,?,?,?,?,?,?,?,?,?)")
    source = once(source, "request.token,request.supply))", "request.token,request.supply,request.operation,"
                  "request.return_tx,request.sequence,request.previous))")
    source = once(source, 'last_observed=intent["disposition"]', 'operation=intent["operation"],'
                  'return_tx=intent["return_tx"].hex(),sequence=intent["sequence"],previous=intent["previous"].hex(),'
                  'last_observed=intent["disposition"]')
    return source


def cli(source):
    source = source.replace("from asset_wallet import Request, default_id, parse_asset",
                            "from asset_wallet import parse_asset\n        from managed_wallet import Request, default_id")
    source = source.replace("from asset_wallet import Request, default_id", "from managed_wallet import Request, default_id")
    source = once(source, "    def resume(", '''    def register(self,name,supply,node,intent=None,wait_seconds=0):
        from managed_wallet import Request, ZERO, default_id
        request=Request(0,ZERO,supply,supply,"register")
        address=self.address(name)
        return self._outgoing(name,node,intent or default_id(address,request),wait_seconds,address,request)

    def mint(self,name,to,asset_id,amount,node,intent=None,wait_seconds=0):
        from asset_wallet import parse_asset
        from managed_wallet import Request, default_id
        request=Request(0,parse_asset(asset_id),amount,amount,"mint")
        address=self.destination(to)
        return self._outgoing(name,node,intent or default_id(address,request),wait_seconds,address,request)

    def burn(self,name,asset_id,amount,return_tx,node,intent=None,wait_seconds=0):
        from asset_wallet import parse_asset
        from managed_wallet import BURN, Request, default_id
        request=Request(0,parse_asset(asset_id),0,BURN+amount,"burn",bytes.fromhex(return_tx))
        address=self.address(name)
        return self._outgoing(name,node,intent or default_id(address,request),wait_seconds,address,request)

    def resume(''')
    source = once(source, "                out.register(ident,address,amount)", """                from managed_wallet import bind_parent
                out.register(ident,address,bind_parent(self,node,out,ident,amount))""")
    source = once(source, '    c=subs.add_parser("issue");', '''    for action in ("register","mint","burn"):
        c=subs.add_parser(action)
        c.add_argument("sender")
        if action=="register":
            c.add_argument("initial_supply",type=int)
        else:
            if action=="mint":
                c.add_argument("recipient")
            c.add_argument("asset_id")
            c.add_argument("amount",type=int)
            if action=="burn":
                c.add_argument("return_tx")
        c.add_argument("--intent");c.add_argument("--wait",type=int,default=0);c.add_argument("--node",choices=NODES,default="c")
    c=subs.add_parser("issue");''')
    return once(source, '    elif args.op=="issue":', '''    elif args.op=="register":
        result=lab.register(args.sender,args.initial_supply,args.node,args.intent,args.wait)
    elif args.op=="mint":
        result=lab.mint(args.sender,args.recipient,args.asset_id,args.amount,args.node,args.intent,args.wait)
    elif args.op=="burn":
        result=lab.burn(args.sender,args.asset_id,args.amount,args.return_tx,args.node,args.intent,args.wait)
    elif args.op=="issue":''')


def stage_wallet(dev):
    dev = Path(dev)
    for name in ("managed_wallet.py", "redemption.py"):
        shutil.copyfile(HERE / name, dev / name)
    shutil.copyfile(AST / "assets.py", dev / "managed_inventory.py")
    for name, specialize in (("asset_wallet", asset_wallet), ("intents", journal), ("cli", cli)):
        path = dev / (name + ".py")
        source = specialize(path.read_text())
        compile(source, str(path), "exec")
        path.write_text(source)
    path = dev / "wallet_sync.py"
    source = once(path.read_text(), '"ast1-wallet-state.sqlite"', '"mng1-wallet-state.sqlite"')
    source = once(source, '                tx=slot["txid"]', '''                tx=slot["txid"]
                require(tx==slot["envelope_digest"],"wallet history transaction differs from the committed envelope")''')
    path.write_text(once(source, 'slot["issue_id"],slot["supply"]))',
                         'slot["issue_id"],slot["supply"],slot["envelope_digest"]))'))
