"""Independently reconstruct field-port packing and verify all hidden wire links/padding."""
from array import array
from collections import Counter
from encoding import COMPACT, MAGIC, ARITY, SHAPE, TERM, U32, f, require


def rows(program):
    kind=program[:8]
    n,cols,count=SHAPE.unpack_from(program,8)
    require(kind in (COMPACT,MAGIC),"invalid program")
    src=memoryview(program)
    pos=20
    for _ in range(count):
        d=2 if kind==MAGIC else src[pos]
        pos+=kind==COMPACT
        operands=[]
        for _ in range(ARITY[d]):
            k,=U32.unpack_from(src,pos)
            pos+=4
            stop=pos+k*TERM.size
            operands.append(dict(TERM.iter_unpack(src[pos:stop])))
            pos=stop
        if kind==MAGIC:
            a,b,c=operands
            if not (a.keys()-{0}) or not (b.keys()-{0}):
                k,var=(b.get(0,0),a) if not (b.keys()-{0}) else (a.get(0,0),b)
                expr={i:(k*t)%f.P for i,t in var.items()}
                for i,t in c.items():
                    expr[i]=(expr.get(i,0)-t)%f.P
                d,operands=1,[{i:t for i,t in expr.items() if t}]
        yield d,operands
    require(pos==len(src),"trailing relation data")


def ports(d):
    return {1:(),2:("a","b","c"),7:("x","y")}[d]


def val(form,z):
    return sum(z[k]*a for k,a in form.items())%f.P


def pack(program,z,width):
    n,cols,_=SHAPE.unpack_from(program,8)
    require(width>=1 and cols==len(z),"invalid packing")
    groups={"w":array("Q",z[1+n:])}
    for degree,forms in rows(program):
        for name,form in zip(ports(degree),forms if degree>1 else (),strict=True):
            if name not in groups:
                groups[name]=array("Q")
            groups[name].append(val(form,z))
    for group in groups.values():
        group.extend([0]*(-len(group)%width))
    return groups


def verify(program,groups,public,width):
    n,cols,_=SHAPE.unpack_from(program,8)
    expected={"w","a","b","c"} | ({"x","y"} if program[:8]==COMPACT else set())
    if type(width) is not int or width<=0 or set(groups)!=expected or len(public)!=n:
        return False
    if any(len(v)%width for v in groups.values()) or any(type(x) is not int or not 0<=x<f.P
            for seq in [public,*groups.values()] for x in seq):
        return False
    used=Counter(w=cols-1-n)
    if len(groups["w"])<used["w"]:
        return False
    z=[1,*public,*groups["w"][:used["w"]]]
    for degree,forms in rows(program):
        if degree==1:
            if val(forms[0],z):
                return False
            continue
        at=used[ports(degree)[0]]
        values=[]
        for name,form in zip(ports(degree),forms,strict=True):
            if at>=len(groups[name]) or groups[name][at]!=val(form,z):
                return False
            values.append(groups[name][at])
            used[name]+=1
        if degree==2 and values[0]*values[1]%f.P!=values[2]:
            return False
        if degree==7 and pow(values[0],7,f.P)!=values[1]:
            return False
    return all(len(group)==used[name]+(-used[name]%width) and not any(group[used[name]:])
               for name,group in groups.items())
