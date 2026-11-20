"""Compile the same funded expression builder to frozen R1CS and mixed linear/quadratic/seventh-power rows."""
from collections import Counter
from hashlib import sha256
import io
import json
from pathlib import Path
import struct
import sys
from types import FunctionType

HERE = Path(__file__).resolve().parent
EX = HERE.parents[1]
sys.path.insert(0, str(EX/"funded-whir/relation"))
import frontend as f

U32 = struct.Struct("<I")
TERM = struct.Struct("<IQ")
SHAPE = struct.Struct("<III")
MAGIC = b"FWHRCS01"
COMPACT = b"TCITHDG7"
ARITY = {1:1, 2:3, 7:2}
REG = {"MNG1":"a1cfa119fe582ecd935734ac51db5d1e6c91af9e0019af737d79791dd688cb9c",
       "SLG1":"2bc9e336428462084efd673d31da240992e25a289e7fa6ab88237f2d568f6f3e"}


def require(condition, label):
    if not condition:
        raise ValueError(label)


def constant(form):
    return all(col == 0 for col in form)


def scaled(form, coeff):
    return f.add((form, coeff))


def as_linear(a, b, c):
    if constant(a):
        return f.sub(scaled(b,a.get(0,0)), c)
    if constant(b):
        return f.sub(scaled(a,b.get(0,0)), c)
    return None


class Circuit(f.Circuit):
    inline = False

    def __init__(self, pub, parameters, output):
        super().__init__(pub,parameters,output)
        self.degrees = Counter()
        self.ports = Counter()
        self.incidences = Counter()
        self.groups = Counter()
        self.private_nnz=0
        self.rhs_terms=0
        self.rhs_rows=0
        self.path_columns = 0
        self.path_perms = 0
        self.sboxes = 0
        self.path_roots = []

    def emit(self, degree, forms):
        self.degrees[degree] += 1
        self.groups[self.label,degree] += 1
        for form in forms:
            self.ports[degree] += 1
            self.incidences[degree] += len(form)
            public_terms=sum(col<=len(self.public) for col in form)
            self.rhs_terms+=public_terms
            self.rhs_rows+=int(public_terms>0)
            self.private_nnz+=len(form)-public_terms+int(degree>1)
        if self.output is not None and self.inline:
            self.output.write(bytes([degree]))
            for form in forms:
                self.output.write(U32.pack(len(form)))
                for col,coeff in sorted(form.items()):
                    self.output.write(TERM.pack(col,coeff))

    def row(self, a, b, c):
        eq = as_linear(a,b,c)
        if eq is None:
            self.emit(2,(a,b,c))
        else:
            self.emit(1,(eq,))
        if self.inline:
            self.rows += 1
        else:
            super().row(a,b,c)

    def path(self, cm, note, active):
        start,perms=len(self.z),self.permutations
        root = super().path(cm,note,active)
        self.path_columns+=len(self.z)-start
        self.path_perms+=self.permutations-perms
        self.path_roots.append(tuple(self.val(v) for v in root))
        return root

    def sbox(self, x):
        self.sboxes += 1
        return super().sbox(x)


class Compact(Circuit):
    inline = True

    def sbox(self, x):
        self.sboxes += 1
        y = self.wire(pow(self.val(x),7,f.P))
        self.emit(7,(x,y))
        self.rows += 1
        return y

    def assign(self, a, b):
        if constant(a):
            return scaled(b,a.get(0,0))
        if constant(b):
            return scaled(a,b.get(0,0))
        return super().assign(a,b)


def compile_program(suite, params, witness, compact=False, *, register=False):
    # The pinned builder accepts a Circuit backend by module global. Give this call
    # its own globals (also supports two simultaneous registrations in one process).
    base = f.compile_relation
    namespace = dict(base.__globals__,Circuit=Compact if compact else Circuit)
    run = FunctionType(base.__code__,namespace,base.__name__,base.__defaults__)
    out = io.BytesIO() if register else None
    c = run(suite,params,witness,out)
    if not register:
        return c
    body = (COMPACT if compact else MAGIC) + SHAPE.pack(f.PUBLIC[suite],len(c.z),c.rows) + out.getvalue()
    if not compact:
        require(sha256(body).hexdigest()==REG[suite],"registered matrix changed")
    return c,body


def evaluate(program,z,public):
    """Read flat frozen bytes, with no calls to the assignment builder or Poseidon code."""
    head = bytes(program[:8])
    require(head in (MAGIC,COMPACT),"unknown relation")
    n,cols,rows = SHAPE.unpack_from(program,8)
    require(len(z)==cols and len(public)==n and z[0]==1 and list(z[1:1+n])==public and
            all(type(v) is int and 0<=v<f.P for v in z),"noncanonical assignment or instance")
    src = memoryview(program)
    at = 20
    ok = True
    for _ in range(rows):
        if head==MAGIC:
            tag=2
        else:
            tag=src[at]
            at+=1
        require(tag in ARITY,"wrong degree")
        values=[]
        for _ in range(ARITY[tag]):
            count,=U32.unpack_from(src,at)
            at+=4
            end=at+TERM.size*count
            values.append(sum(z[col]*scalar for col,scalar in TERM.iter_unpack(src[at:end]))%f.P)
            at=end
        if tag==1:
            ok &= values[0]==0
        elif tag==2:
            ok &= values[0]*values[1]%f.P==values[2]
        else:
            ok &= pow(values[0],7,f.P)==values[1]
    require(at==len(src),"trailing relation bytes")
    return ok


def canonical(w):
    suite=w["suite"]
    def vector(obj,n):
        require(type(obj) is list and len(obj)==n and all(type(v) is int and 0<=v<f.P for v in obj),
                "invalid private/public field vector")
    require(suite in REG and type(w["depth"]) is int and 0<=w["depth"]<=20,"invalid relation or path depth")
    vector(w["header"],45)
    vector(w["public"],f.PUBLIC[suite])
    vector(w["ct_digest"],4)
    vector(w["asset_id"],4)
    vector([w["fee"],w["delta"]],2)
    if suite=="SLG1":
        vector(w["auth_key"],8)
    require(len(w["inputs"])==len(w["outputs"])==2,"incorrect note count")
    for note in w["inputs"]:
        for name in ("ask","nk","rho","raw"):
            vector(note[name],4)
        vector([note["value"],note["token"]],2)
        require(type(note["dummy"]) in (bool,int) and note["dummy"] in (0,1),"invalid dummy bit")
        levels,locations=note["siblings"],note["positions"]
        require(type(levels) is list and type(locations) is list and len(levels)==len(locations) and
                (len(levels)==w["depth"] or note["dummy"] and not levels),"path length mismatch")
        for level,j in zip(levels,locations,strict=True):
            require(type(j) is int and 0<=j<4 and type(level) is list and len(level)==3,"invalid path structure")
            for sib in level:
                vector(sib,4)
    for note in w["outputs"]:
        vector(note["pk"],4)
        vector(note["raw"],4)
        vector([note["value"],note["token"]],2)


def census(c,program,suite):
    base=f.PUBLIC[suite]
    # This column-group accounting treats every gate input/output port as a separate vector.
    # Each nonlinear port is tied to its affine form on the independent assignment.
    residual={d:c.degrees[d]-c.groups["path position or membership",d] for d in c.degrees}
    without_path=dict(private_columns=len(c.z)-1-base-c.path_columns, rows_by_degree=residual,
                      permutations=c.permutations-c.path_perms, seventh_powers=c.sboxes-118*c.path_perms,
                      packing_groups=[len(c.z)-1-base-c.path_columns]+[residual[2]]*3+([residual[7]]*2 if c.inline else []))
    groups=[len(c.z)-1-base]+[c.degrees[2]]*3+([c.degrees[7]]*2 if c.inline else [])
    tails=[-n%101 for n in groups]
    linear_rows=c.degrees[1]+c.ports[2]+c.ports[7]
    by_label={label:{str(d):c.groups[label,d] for d in (1,2,7) if c.groups[label,d]}
              for label in sorted({label for label,_ in c.groups})}
    return dict(counts_by_builder_label=by_label,
                packing_at_101=dict(group_packs=[(n+100)//101 for n in groups],group_zero_tails=tails,
                                    padded_global_rows=linear_rows+sum(tails),
                                    padded_private_matrix_nnz=c.private_nnz+sum(tails)),
                without_two_path_evaluations_and_terminal_links=without_path,serialized_shape_sha256=sha256(program).hexdigest(),serialized_shape_B=len(program),
                public_words=base,private_columns=len(c.z)-1-base,rows=c.rows,permutations=c.permutations,
                seventh_powers=c.sboxes,rows_by_degree=dict(sorted(c.degrees.items())),
                equation_form_nnz=dict(sorted(c.incidences.items())),
                nonlin_port_equality_rows=c.ports[2]+c.ports[7],
                linear_wiring_equations=linear_rows,
                wiring_nnz_before_cancelling_port_coefficients=sum(c.incidences.values())+c.ports[2]+c.ports[7],
                global_matrix_private_nnz=c.private_nnz,known_rhs_affine_nnz=c.rhs_terms,
                rows_with_structural_public_or_constant_rhs=c.rhs_rows,
                packing_groups=groups,
                baseline_ABC_nnz=c.terms if not c.inline else None)


def registration(params):
    shapes={}
    programs={}
    for suite in REG:
        shapes[suite]={}
        programs[suite]=[]
        for compact,name in ((False,"r1cs"),(True,"degree7")):
            c,program=compile_program(suite,params,f.blank(suite),compact,register=True)
            shapes[suite][name]=census(c,program,suite)
            programs[suite].append(program)
    return shapes,programs


if __name__=="__main__":
    print(json.dumps(registration(f.constants(Path(sys.argv[1])))[0],indent=2))
