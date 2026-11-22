"""Batched §6.2 Keccak GKR on K flattened contiguous round groups per permutation."""
import numpy as np
from cbip import sumcheck
from runtime import U, eq_table, mul, product, xor

N = 1600
PAD = 2048
ROT = (0,1,62,28,27,36,44,6,55,20,3,10,43,25,39,41,45,15,21,8,18,2,61,56,14)


def maps():
    off = np.empty((N,11),np.int32)
    for y in range(5):
        for x in range(5):
            lane = x+5*y
            target = y+5*((2*x+3*y)%5)
            for z in range(64):
                a = [64*lane+z]
                a += [64*((x+4)%5+5*j)+z for j in range(5)]
                a += [64*((x+1)%5+5*j)+(z-1)%64 for j in range(5)]
                off[64*target+(z+ROT[lane])%64] = a
    return tuple(np.roll(off.reshape(5,5,64,11),-k,axis=1).reshape(N,11) for k in range(3))


MAP = maps()
RC = np.zeros((24,N),np.uint8)
lfsr = 1
for i in range(24):
    for j in range(7):
        RC[i,(1<<j)-1] = lfsr&1
        lfsr = ((lfsr<<1)&255)^(0x71 if lfsr&128 else 0)


def lanes(states):
    return [np.bitwise_xor.reduce(states[...,m],axis=-1) for m in MAP]


def forward(initial):
    out = np.empty((25,N),np.uint8)
    out[0] = initial
    for i in range(24):
        a,l,r = lanes(out[i])
        out[i+1] = RC[i]^a^((1^l)&r)
    return out


def linear_map_weights(rx):
    weights = eq_table(rx)[:N]
    result = []
    for mapping in MAP:
        a = np.zeros(PAD,U)
        for col in mapping.T:
            np.bitwise_xor.at(a,col,weights)
        result.append(a)
    return result


def state_projection(ids,wx,wz):
    def apply(out,scale):
        for row,z in zip(ids,wz):
            # Shared IDs across boundary slices contribute with field addition.
            np.bitwise_xor.at(out,row,mul(wx[:N],mul(scale,z)))
    return apply


def state_value(states,wx,wz):
    v = xor(np.where(states,wz[:len(states),None],0),axis=0)
    return xor(mul(v,wx[:N]))


class RoundBatch:
    def __init__(self,boundary_ids,states=None):
        self.ids = np.asarray(boundary_ids)
        self.p,k1,n = self.ids.shape
        self.k = k1-1
        if not self.p or self.k < 1 or 24%self.k or n!=N:
            raise ValueError("invalid round batch")
        self.depth = 24//self.k
        self.count = self.p*self.k
        self.zbits = (self.count-1).bit_length()
        self.ell = 11+self.zbits
        self.input_ids = self.ids[:,:-1].reshape(-1,N)
        self.output_ids = self.ids[:,1:].reshape(-1,N)
        self.starts = np.tile(np.arange(self.k)*self.depth,self.p)
        self.parent = np.repeat(np.arange(self.p),self.k)
        self.states = states
        if states is not None and states.shape != (self.p,25,N):
            raise ValueError("wrong round trace shape")

    def stage(self,i):
        return self.states[self.parent,self.starts+i]

    @property
    def mask_count(self):
        return 1+self.depth*(3*self.ell+3)+(self.depth-1)*23


def run_rounds(batch,ctx):
    tr = ctx.tr
    rx = tr.challenge(b"Keccak output state index",11)
    rz = tr.challenge(b"flattened permutation index",batch.zbits)
    wx,wz = eq_table(rx),eq_table(rz)
    initial = [state_value(batch.stage(batch.depth),wx,wz)] if tr.producing else None
    claim = ctx.masked(b"masked output state MLE",1,initial)[0]
    ctx.bind(state_projection(batch.output_ids,wx,wz),claim)
    for i in reversed(range(batch.depth)):
        const = state_value(RC[batch.starts+i],wx,wz)
        claim = claim^ctx.form(const)
        arrays = None
        if tr.producing:
            o,l,r = lanes(batch.stage(i))
            def pad(v):
                b = np.zeros((1<<batch.zbits,PAD),np.uint8)
                b[:batch.count,:N] = v
                return b.ravel().astype(U)
            arrays = (eq_table([*rx,*rz]),pad(o),pad(l),pad(r))
        def gate(e,o,l,r):
            return mul(e,o^mul(1^l,r))
        end,coords,final = sumcheck(ctx,claim,batch.ell,3,arrays,gate,b"Keccak chi sumcheck")
        sx,sz = coords[:11],coords[11:]
        wz_next = eq_table(sz)
        # eq at the endpoint is public, including padded/cross-slice equality weights.
        eq = product(np.array([1^a^b for a,b in zip([*rx,*rz],coords)],U))
        f = ctx.masked(b"Keccak affine-map MLEs",3,final[1:] if tr.producing else None)
        off,left,right = f
        ctx.product(mul(eq,ctx.form(1)^left),right,end^mul(eq,off))
        map_weights = linear_map_weights(sx)
        if i == 0:
            for row_weights,form in zip(map_weights,f):
                ctx.bind(state_projection(batch.input_ids,row_weights,wz_next),form)
            break
        # The maps are independent of the batch index z. Hold sz fixed and sum only over y.
        mix = tr.challenge(b"combine Keccak maps",3)
        matrix = xor(mul(np.asarray(map_weights,U),mix[:,None]),axis=0)
        start = xor(mul(np.asarray(f,U),mix[:,None]),axis=0)
        arrays = None
        if tr.producing:
            prev = np.zeros(PAD,U)
            prev[:N] = xor(np.where(batch.stage(i),wz_next[:batch.count,None],0),axis=0)
            arrays = (matrix,prev)
        end,rx,terminal = sumcheck(ctx,start,11,2,arrays,mul,b"Keccak linear map sumcheck")
        wx,wz,rz = eq_table(rx),wz_next,sz
        claim = ctx.masked(b"previous state MLE",1,[terminal[1]] if tr.producing else None)[0]
        ctx.linear(end^mul(claim,xor(mul(matrix,wx))))
