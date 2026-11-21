// Two independently blinded broadcasts for each of the five verification batches.
#pragma once
#include "relation.hpp"
#include "commitment.hpp"

constexpr std::array<unsigned,8> ZeroOffsets{0,117,234,351,468,585,702,771};
constexpr std::array<unsigned,2> SumOffsets{0,116};
static_assert(ZeroOffsets.back()+D==PolyDegree-S && SumOffsets.back()+D==LinearDegree);

inline Matrix share(const Domain& domain,const Words& slots) {
    Words grid=domain.omega;
    grid.insert(grid.end(),domain.canonical.begin(),domain.canonical.begin()+L);
    Matrix bs=basis(grid), polys;
    RandomWords random;
    for (unsigned j=0;j<Witness;++j) {
        Words values(slots.begin()+S*j,slots.begin()+S*(j+1));
        for (unsigned k=0;k<L;++k) values.push_back(random.field());
        polys.push_back(coefficients(bs,values));
    }
    for (unsigned r=0;r<Rho;++r) {
        unsigned first=polys.size();
        for (unsigned j=0;j<Hints;++j) polys.push_back(random.words(D+1));
        Word total=0;
        for (Word w:domain.omega)
            for (unsigned j=0;j<SumOffsets.size();++j)
                total=add(total,mul(power(w,SumOffsets[j]),eval(polys[first+ZeroOffsets.size()+j],w)));
        Word& c=polys[first+ZeroOffsets.size()][0];
        c=sub(c,mul(total,power(S,P-2)));
    }
    for (unsigned i=0;i<Eta;++i) polys.push_back(random.words(D+1));
    return polys;
}
inline Matrix degree_matrix(Hashes& hashes,const Digest& h1) {
    Stream stream(hashes,'G',{h1});
    Matrix gamma(Eta,Words(Q));
    for (auto& row:gamma) for (Word& x:row) x=stream.field();
    return gamma;
}
inline Words local_xi(const Words& row,const Matrix& gamma) {
    Words out(Eta);
    for (unsigned j=0;j<Eta;++j) {
        Word v=row[Q+j];
        for (unsigned k=0;k<Q;++k) v=add(v,mul(row[k],gamma[j][k]));
        out[j]=v;
    }
    return out;
}
inline Matrix degree_polys(const Matrix& polys,const Matrix& gamma) {
    Matrix out(polys.begin()+Q,polys.end());
    for (unsigned i=0;i<Eta;++i)
        for (unsigned j=0;j<Q;++j)
            for (unsigned k=0;k<=D;++k) out[i][k]=add(out[i][k],mul(polys[j][k],gamma[i][j]));
    return out;
}
inline Words values_at(const Matrix& polys,Word x) {
    Words out;
    out.reserve(polys.size());
    for (const auto& p:polys) out.push_back(eval(p,x));
    return out;
}
struct Batch {
    Words gates;
    Matrix columns;
    Word rhs=0;
};
struct Batches {
    std::array<Batch,Rho> batches;
    std::array<unsigned,6> blocks{};
    Words vanishing;
    Batches(const Domain& domain,const Relation& relation,Hashes& hashes,const Digest& h1,const Digest& h2):
        vanishing(vanish_poly(domain.omega)) {
        for (unsigned i=0;i<6;++i) blocks[i]=relation.start[i]/S;
        Matrix bs=basis(domain.omega);
        Stream stream(hashes,'B',{h1,h2});
        for (Batch& batch:batches) {
            unsigned gates=(GroupLength[1]+S-1)/S+(GroupLength[4]+S-1)/S;
            for (unsigned i=0;i<gates;++i) batch.gates.push_back(stream.field());
            Words projection(S*Witness);
            for (const Equation& row:relation.rows) {
                Word weight=stream.field();
                batch.rhs=sub(batch.rhs,mul(weight,row.known));
                for (auto& term:row.hidden) {
                    Word& v=projection[term.index];
                    v=add(v,mul(weight,term.scalar));
                }
            }
            for (unsigned j=0;j<Witness;++j) {
                Words column(projection.begin()+S*j,projection.begin()+S*(j+1));
                batch.columns.push_back(coefficients(bs,column));
            }
        }
    }
    std::array<Word,Rho> nonlinear(const Words& row,Word x) const {
        Words gates;
        unsigned quad=blocks[2]-blocks[1], seventh=blocks[5]-blocks[4];
        for (unsigned j=0;j<quad;++j)
            gates.push_back(sub(mul(row[blocks[1]+j],row[blocks[2]+j]),row[blocks[3]+j]));
        for (unsigned j=0;j<seventh;++j) {
            Word v=row[blocks[4]+j], v2=mul(v,v), v4=mul(v2,v2);
            gates.push_back(sub(mul(mul(v4,v2),v),row[blocks[5]+j]));
        }
        Word z=eval(vanishing,x);
        std::array<Word,ZeroOffsets.size()> shift{};
        for (unsigned j=0;j<shift.size();++j) shift[j]=power(x,ZeroOffsets[j]);
        std::array<Word,Rho> result{};
        for (unsigned i=0;i<Rho;++i) {
            Word mask=0;
            for (unsigned j=0;j<shift.size();++j) mask=add(mask,mul(row[Witness+i*Hints+j],shift[j]));
            result[i]=add(dot(batches[i].gates,gates),mul(z,mask));
        }
        return result;
    }
    std::array<Word,Rho> linear(const Words& row,Word x) const {
        std::array<Word,Rho> result{};
        Word shift=power(x,SumOffsets[1]);
        for (unsigned i=0;i<Rho;++i) {
            unsigned off=Witness+i*Hints+ZeroOffsets.size();
            Word v=add(row[off],mul(shift,row[off+1]));
            for (unsigned j=0;j<Witness;++j) v=add(v,mul(row[j],eval(batches[i].columns[j],x)));
            result[i]=v;
        }
        return result;
    }
};
inline Digest broadcast_digest(Hashes& hashes,const Matrix& polynomial,const Matrix& linear) {
    Bytes ordered;
    for (unsigned i=0;i<Rho;++i) {
        append_words(ordered,polynomial[i]); append_words(ordered,linear[i]);
    }
    return hashes.data('A',ordered);
}
