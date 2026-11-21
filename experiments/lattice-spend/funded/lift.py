"""Price an exact binary polynomial lift of the funded Goldilocks relations into R_q."""
import argparse
from collections import Counter
from functools import lru_cache
import json
from pathlib import Path
import sys

HERE = Path(__file__).resolve().parent
EX = HERE.parents[1]
sys.path.insert(0, str(EX/"packed-tcith/encoding"))
import encoding
from packed import rows

P = 2**64 - 2**32 + 1
Q = 2**38 - 107
D = 256
# Space between binary coefficients in the independent integer convolution oracle.
STRIDE = 32


@lru_cache(maxsize=32768)
def expanded(word):
    """Embed the bits at powers of 2^32. Products compute ordinary convolution."""
    if word < 0:
        raise ValueError("unsigned word required")
    return int.from_bytes(b"".join(((word>>i)&1).to_bytes(4,"little") for i in range(word.bit_length())), "little")


def schedule(max_sum, plus_height, plus_width, output):
    """The quotient is bounded on honest inputs. Each carry gets an exact signed bit range."""
    k = (max_sum//P).bit_length()
    length = max(plus_width, (P.bit_length()+k-1) if k else 0, 64 if output else 0)
    raw = max(plus_height, min(P.bit_count(),k)+int(output))
    h = max(1,raw.bit_length()+1)
    if length > D or raw+3*(1<<(h-1)) >= Q or raw >= 1<<STRIDE:
        raise ValueError("coefficient or ring capacity exceeded")
    return k, max(length-1,0), h


def open_equation(total, lhs, out, sched, *, corrupt=False):
    """Check each coefficient, the bounded quotient and terminal carry. Never return witness values."""
    kbits, carry_len, bits = sched
    k,rem = divmod(total-out, P)
    if k < 0 or k.bit_length()>kbits or rem:
        return False
    rhs = expanded(P)*expanded(k)+expanded(out)
    carry = 0
    for i in range(carry_len+1):
        delta=(lhs & 0xffffffff)-(rhs & 0xffffffff)+carry
        nxt=delta//2 if i<carry_len else 0
        if corrupt and i==0:
            nxt+=1
        if not -(1<<(bits-1)) <= nxt < 1<<(bits-1) or (delta-2*nxt)%Q:
            return False
        carry=nxt
        lhs >>= STRIDE
        rhs >>= STRIDE
    return (lhs,rhs,carry)==(0,0,0)


def canonical_word(v):
    if not 0<=v<1<<64:
        return False
    slack=P-1-v
    if not 0<=slack<1<<64:
        return False
    carry=0
    for i in range(64):
        a=((v>>i)&1)+((slack>>i)&1)+carry-(((P-1)>>i)&1)
        nxt=a//2 if i<63 else 0
        if nxt not in (0,1) or (a-2*nxt)%Q:
            return False
        carry=nxt
    return carry==0


class Census:
    def __init__(self, program, assignment=None):
        self.public, columns, self.source_rows=encoding.SHAPE.unpack_from(program,8)
        self.z=assignment
        self.n=Counter(canonical_words=columns-1-self.public)
        self.unique={}
        if assignment is not None and any(not canonical_word(z) for z in assignment):
            raise ValueError("noncanonical field opening")
        for d,forms in rows(program):
            if d==1:
                self.affine(forms[0],0,False)
            else:
                values=[self.operand(form) for form in forms]
                if d==2:
                    self.multiply(*values, quadratic=all(any(i>self.public for i in form) for form in forms[:2]))
                elif d==7:
                    self.n['canonical_words']+=3
                    x,y=values
                    if self.z is None:
                        tmp=[0]*3
                    else:
                        tmp=[pow(x,i,P) for i in (2,4,6)]
                        if not all(map(canonical_word, tmp)):
                            raise ValueError('invalid internal residue')
                    secret_x=any(i>self.public for i in forms[0])
                    self.multiply(x,x,tmp[0],quadratic=secret_x)
                    self.multiply(tmp[0],tmp[0],tmp[1])
                    self.multiply(tmp[0],tmp[1],tmp[2])
                    self.multiply(tmp[2],x,y,quadratic=secret_x)
                else:
                    raise ValueError("unknown row")
        self.n['materialized_affines']=len(self.unique)

    def operand(self,form):
        if not any(col>self.public for col in form):
            return sum(self.z[i]*v for i,v in form.items())%P if self.z is not None else 0
        if len(form)==1:
            col,coeff=next(iter(form.items()))
            if coeff==1:
                return self.z[col] if self.z is not None else 0
        key=tuple(sorted(form.items()))
        if key not in self.unique:
            out=sum(self.z[i]*v for i,v in form.items())%P if self.z is not None else 0
            if self.z is not None and not canonical_word(out):
                raise ValueError('invalid materialized port')
            self.affine(form,out,True)
            self.unique[key]=out
            self.n['canonical_words']+=1
        return self.unique[key]

    def add_relation(self,total,lhs,out,sched,kind):
        k,l,h=sched
        self.n[kind]+=1
        self.n['quotient_polys']+=int(k>0)
        self.n['carry_bit_planes']+=h if l else 0
        self.n['quotient_bits']+=k
        self.n['carry_bits']+=l*h
        self.n['max_carry_width']=max(self.n['max_carry_width'],h)
        if self.z is not None and not open_equation(total,lhs,out,sched):
            raise ValueError("non-native equation failed")

    def affine(self,form,out,materialize):
        # Public fields are verifier constants fixed by the real 31/34-word statement.
        # Uniform upper bounds permit one template for all public values.
        if not form:
            if out: raise ValueError("invalid constant")
            return
        private=[(i,v) for i,v in form.items() if i>self.public]
        maximum=sum(v*(1 if i==0 else P-1) for i,v in form.items())
        height=sum(v.bit_count() for v in form.values())
        width=max(v.bit_length()+(0 if i==0 else 63) for i,v in form.items())
        shape=schedule(maximum,height,width,materialize)
        total=lhs=0
        if self.z is not None:
            total=sum(self.z[i]*v for i,v in form.items())
            lhs=sum(expanded(self.z[i])*expanded(v) for i,v in form.items())
        self.n['affine_private_terms']+=len(private)
        self.add_relation(total,lhs,out,shape,'linear_reductions')

    def multiply(self,a,b,c,*,quadratic=True):
        self.n['private_quadratic_rows']+=int(quadratic)
        shape=schedule((P-1)**2,64,127,True)
        self.add_relation(a*b,expanded(a)*expanded(b),c,shape,'product_reductions')

    def result(self):
        n=self.n
        words=n['canonical_words']
        # W,S,C for each canonical word; K and each carry bit plane per reduction.
        polys=3*words+n['quotient_polys']+n['carry_bit_planes']
        live_bits=words*(64+64+63)+n['quotient_bits']+n['carry_bits']
        support=(polys+1023)//1024
        return {**dict(n), 'public_words':self.public, 'original_rows':self.source_rows,
                'ring_degree':D,'proof_modulus':Q,'binary_polynomials':polys,
                'live_binary_positions':live_bits,'padding_positions':D*polys-live_bits,
                'support_checks':support,'canonical_addition_checks':words,
                'full_ring_equations':words+n['product_reductions']+n['linear_reductions'],
                'raw_native_witness_coefficient_bytes':2*D*polys}


def tests():
    a=P-2; b=P-3; correct=a*b%P
    shape=schedule((P-1)**2,64,127,True)
    assert canonical_word(a) and canonical_word(0) and canonical_word(P-1) and not canonical_word(P)
    # Independent negacyclic constant-term check of the padding equation.
    # One valid binary input and two different invalid hidden tail placements.
    def padding_ct(ones, width):
        mask = {D-j:-1 for j in range(max(width,1),D)}
        if width == 0:
            mask[0] = 1
        return sum(mask.get(0,0) if j==0 else -mask.get(D-j,0) for j in ones) % Q
    assert padding_ct([0,12,63],64)==0
    assert padding_ct([0,64],64)==1 and padding_ct([255],64)==1
    assert padding_ct([0],0)==1 and 1024*D<Q
    assert open_equation(a*b,expanded(a)*expanded(b),correct,shape)
    assert not open_equation(a*b,expanded(a)*expanded(b),correct+1,shape)
    assert not open_equation(a*b,expanded(a)*expanded(b),correct,shape,corrupt=True)
    assert (a*b-correct)%Q != 0 and (a*b-correct)%P == 0


def main(constants):
    tests()
    params=encoding.f.constants(constants)
    result={}
    for suite in ('MNG1','SLG1'):
        _,sealed=encoding.compile_program(suite, params, encoding.f.blank(suite), True,register=True)
        result[suite]=Census(sealed).result()
    return result


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('poseidon_constants',type=Path)
    print(json.dumps(main(parser.parse_args().poseidon_constants),indent=2,sort_keys=True))
