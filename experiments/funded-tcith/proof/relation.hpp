// The legacy direct shape defines every hidden wire, affine form and nonlinear port.
#pragma once
#include "field.hpp"
constexpr unsigned Public=38, Private=16818;
constexpr std::array<unsigned,6> GroupLength{Private,2099,2099,2099,14632,14632};
constexpr char ShapeHex[]="77533cc1c383bec78358ae8b304a1151aab834c34656d2edcc167dccdaf1c339";
struct Term { unsigned index; Word scalar; };
struct Equation { std::vector<Term> hidden; Word known; };
struct Relation {
    std::array<unsigned,6> start{};
    std::vector<Equation> rows;
    Words slots; // allocated only in the prover, includes all per-group zero padding
    explicit Relation(const Bytes& program,const Words& pub,const Words* w) {
        need(pub.size()==Public && (!w || w->size()==Private),"assignment length");
        unsigned used=0;
        for (unsigned i=0;i<6;++i) {
            start[i]=used;
            used+=((GroupLength[i]+S-1)/S)*S;
        }
        need(used==Witness*S,"packed width");
        if (w) {
            slots.resize(used);
            std::copy(w->begin(),w->end(),slots.begin());
        }
        Reader in{program};
        need(!std::memcmp(in.take(8),"TCITHDG7",8) && in.u32()==Public &&
             in.u32()==1+Public+Private && in.u32()==16833,"circuit dimensions");
        std::array<unsigned,6> counts{Private,0,0,0,0,0};
        for (unsigned i=0;i<16833;++i) {
            unsigned d=*in.take(1);
            need(d==1||d==2||d==7,"unregistered degree");
            unsigned arity=d==1?1:d==2?3:2;
            Word ports[3]{};
            for (unsigned j=0;j<arity;++j) {
                unsigned terms=in.u32();
                Equation eq{{},0};
                Word value=0;
                for (unsigned k=0;k<terms;++k) {
                    unsigned col=in.u32();
                    Word c=in.field();
                    need(col<1+Public+Private,"bad column");
                    if (col<=Public) {
                        eq.known=add(eq.known,mul(c,col==0?1:pub[col-1]));
                    } else {
                        unsigned idx=col-1-Public;
                        eq.hidden.push_back({idx,c});
                        if (w) value=add(value,mul(c,(*w)[idx]));
                    }
                }
                value=add(value,eq.known);
                if (d!=1) {
                    unsigned g=(d==2?1:4)+j;
                    need(counts[g]<GroupLength[g],"port count");
                    unsigned idx=start[g]+counts[g]++;
                    eq.hidden.push_back({idx,P-1});
                    if (w) slots[idx]=ports[j]=value;
                } else if (w) need(value==0,"unsatisfied affine constraint");
                rows.push_back(std::move(eq));
            }
            if (w && d==2) need(mul(ports[0],ports[1])==ports[2],"unsatisfied quadratic constraint");
            if (w && d==7) need(power(ports[0],7)==ports[1],"unsatisfied seventh-power constraint");
        }
        in.end();
        need(counts==GroupLength,"missing ports");
        for (unsigned g=0;g<6;++g) {
            unsigned end=g==5?used:start[g+1];
            for (unsigned i=start[g]+GroupLength[g];i<end;++i) rows.push_back({{{i,1}},0});
        }
        need(rows.size()==35934,"linear census");
    }
};
