// Compile the verifier-owned 99-permutation SGM1 relation, with CPython allocation order.
#include "wiring.hpp"
#include <algorithm>
#include <numeric>
#include <stdexcept>

namespace sgm {
namespace {
using ByteVec = std::vector<uint8_t>;
IDs span(const IDs& a,size_t i,size_t j) {return IDs(a.begin()+i,a.begin()+j);}
IDs cat(const std::vector<IDs>& chunks) {
    IDs v;
    for(const auto& s:chunks) v.insert(v.end(),s.begin(),s.end());
    return v;
}
IDs bits(const ByteVec& a) {
    IDs b; b.reserve(8*a.size());
    for(uint8_t x:a) for(unsigned i=0;i<8;++i) b.push_back((x>>i)&1);
    return b;
}
uint64_t le(const ByteVec& a,size_t start,size_t len) {
    uint64_t y=0;
    for(size_t i=0;i<len;++i) y|=uint64_t(a.at(start+i))<<(8*i);
    return y;
}
}
IDs Setup::alloc(size_t n) {
    IDs a(n); std::iota(a.begin(),a.end(),width); width+=n; return a;
}
void Setup::pin(const IDs& a,IDs b) { linear.push_back({{a},std::move(b)}); }
void Setup::equal(const IDs& a,const IDs& b) {linear.push_back({{a,b},IDs(a.size(),0)});}
IDs Setup::xor2(const IDs& a,const IDs& b) {
    IDs z=alloc(a.size());
    linear.push_back({{a,b,z},IDs(a.size(),0)});
    return z;
}
IDs Setup::product(const IDs& a,const IDs& b) {
    IDs z=alloc(a.size());
    scalar[0].insert(scalar[0].end(),a.begin(),a.end());
    scalar[1].insert(scalar[1].end(),b.begin(),b.end());
    scalar[2].insert(scalar[2].end(),z.begin(),z.end());
    return z;
}
IDs Setup::gate(const IDs& x,const IDs& b) { return product(x,IDs(x.size(),b[0])); }
IDs Setup::nonzero(IDs x) {
    x=xor2(x,IDs(x.size(),1));
    while(x.size()>1) {
        IDs a,b;
        for(size_t k=0;k+1<x.size();k+=2) {a.push_back(x[k]);b.push_back(x[k+1]);}
        IDs z=product(a,b);
        if(x.size()&1) z.push_back(x.back());
        x=std::move(z);
    }
    return xor2(x,{1});
}
IDs Setup::add(IDs a,IDs b) {
    a.resize(66,0); b.resize(66,0);
    auto p=xor2(a,b); auto g=product(a,b);
    IDs c{0},cs;
    for(size_t i=0;i<66;++i) {
        cs.push_back(c[0]);
        auto t=product({p[i]},c); c=xor2({g[i]},t);
    }
    pin(c,{0}); return xor2(p,cs);
}
IDs Setup::permute(IDs a) {
    if(a.size()!=1600) throw std::logic_error("permutation width");
    std::array<IDs,5> rows;
    rows[0]=std::move(a);
    for(unsigned i=1;i<5;++i) rows[i]=alloc(1600);
    boundary.push_back(std::move(rows));
    return boundary.back()[4];
}
IDs Setup::shake(uint8_t tag,const std::vector<IDs>& parts) {
    IDs raw=bits({0xf1,tag}),payload=cat(parts);
    raw.insert(raw.end(),payload.begin(),payload.end());
    ByteVec pad(136-(raw.size()/8)%136,0);
    pad[0]=0x1f;pad.back()|=0x80;
    raw=cat({raw,bits(pad)});
    IDs prev;
    for(size_t pos=0;pos<raw.size();pos+=1088) {
        auto rate=span(raw,pos,pos+1088);
        IDs cap(512,0);
        if(!prev.empty()) { rate=xor2(rate,span(prev,0,1088)); cap=span(prev,1088,1600); }
        prev=permute(cat({rate,cap}));
    }
    return span(prev,0,512);
}
void Setup::below(const IDs& idx,uint64_t count) {
    if(count==(1ULL<<40)) return;
    IDs less{0};
    for(size_t i=0;i<40;++i) {
        IDs x{idx[i]};
        if((count>>i)&1) {
            auto flipped=xor2(less,{1}); auto t=product(x,flipped); less=xor2({1},t);
        } else {
            auto flipped=xor2(x,{1}); less=product(flipped,less);
        }
    }
    pin(less,{1});
}
Setup::Setup(const ByteVec& s) {
    if(s.size()!=526) throw std::invalid_argument("statement length");
    auto pub=[&](size_t i,size_t j){return bits(ByteVec(s.begin()+i,s.begin()+j));};
    auto count=le(s,128,6);
    if(!count||count>(1ULL<<40)||std::equal(s.begin()+142,s.begin()+206,s.begin()+206))
        throw std::invalid_argument("invalid monetary statement");
    const auto chain=pub(0,64),root=pub(64,128);
    pin({0,1},{0,1});
    auto active=alloc(1); auto inactive=xor2(active,{1}); auto common=alloc(512);
    std::array<IDs,2> asks,idxs,records;
    std::array<std::array<IDs,3>,4> notes;
    for(size_t slot=0;slot<2;++slot) {
        auto ask=alloc(512); auto occ=alloc(512); auto native=alloc(64); auto asset=alloc(512);
        auto qty=alloc(64); auto salt=alloc(512); auto idx=alloc(40);
        asks[slot]=ask;idxs[slot]=idx;records[slot]=cat({ask,native,asset,qty,salt,occ,idx});
        notes[slot]={native,asset,qty};
        auto owner=shake(3,{ask}); auto cm=shake(4,{chain,owner,native,asset,qty,salt});
        auto cur=shake(5,{occ,cm}); below(idx,count);
        for(unsigned level=0;level<40;++level) {
            auto sib=alloc(512); auto left=alloc(512);
            selectors.push_back({cur,sib,left,idx[level]});
            auto right=alloc(512);
            linear.push_back({{cur,sib,left,right},IDs(512,0)});
            cur=shake(7,{bits({uint8_t(level)}),left,right});
        }
        pin(cur,root);
        IDs nf;
        if(slot==0) nf=shake(8,{ask,occ});
        else {
            auto tag=bits({8});tag[0]=inactive[0];
            nf=span(permute(cat({bits({0xf1}),tag,ask,occ,bits({0x1f,0,0,0,0,0x80}),IDs(512,0)})),0,512);
        }
        pin(nf,pub(142+64*slot,206+64*slot));
    }
    equal(nonzero(xor2(idxs[0],idxs[1])),active);
    auto diff=xor2(records[0],records[1]); pin(gate(diff,inactive),IDs(diff.size(),0));
    for(size_t slot=0;slot<2;++slot) {
        auto owner=alloc(512);auto native=alloc(64);auto asset=alloc(512);
        auto qty=alloc(64);auto salt=alloc(512);
        notes[slot+2]={native,asset,qty};
        auto cm=shake(4,{chain,owner,native,asset,qty,salt});
        pin(cm,pub(270+64*slot,334+64*slot));
    }
    std::vector<IDs> qnz;
    for(const auto& n:notes) qnz.push_back(nonzero(n[2]));
    auto nzc=nonzero(common); auto nzq=nonzero(cat(qnz)); equal(nzc,nzq);
    for(size_t i=0;i<4;++i) {
        equal(notes[i][1],gate(common,qnz[i]));
        if(i<2) pin(nonzero(cat({notes[i][0],qnz[i]})),{1});
    }
    for(size_t f: {0,2}) {
        auto gated=gate(notes[1][f],active);auto lhs=add(notes[0][f],gated);
        auto rhs=add(notes[2][f],notes[3][f]);
        if(f==0) rhs=add(rhs,pub(134,142));
        equal(lhs,rhs);
    }
    pin(shake(10,{asks[0],pub(398,462)}),pub(462,526));
    if(boundary.size()!=99||selectors.size()!=80) throw std::logic_error("registered dimensions");
}
}
