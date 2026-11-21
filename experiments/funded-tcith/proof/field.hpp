// Goldilocks arithmetic and interpolation for the fixed SLG1 registration.
#pragma once
#include <algorithm>
#include <array>
#include <cstdint>
#include <cstring>
#include <fstream>
#include <iostream>
#include <map>
#include <memory>
#include <set>
#include <stdexcept>
#include <string>
#include <vector>
#include <openssl/evp.h>
#include <openssl/rand.h>

using Word = uint64_t;
using Bytes = std::vector<unsigned char>;
using Words = std::vector<Word>;
using Matrix = std::vector<Words>;
using Digest = std::array<unsigned char, 64>;
constexpr Word P = 0xffffffff00000001ULL;
constexpr unsigned N = 1 << 18, K = 256, S = 117, L = 32, D = S+L-1;
constexpr unsigned Rho = 5, Eta = 33, Witness = 450, Hints = 10, Q = Witness+Rho*Hints, Width = Q+Eta;
constexpr unsigned PolyDegree = 7*D, LinearDegree = 2*S+L-2, MaxProof = 239976;

inline void need(bool ok, const char* error) { if (!ok) throw std::runtime_error(error); }
inline Word add(Word x, Word y) {
    Word z = x+y;
    return z<x || z>=P ? z-P : z;
}
inline Word sub(Word x, Word y) { return x>=y ? x-y : P-(y-x); }
inline Word mul(Word x, Word y) { return Word((__uint128_t(x)*y)%P); }
inline Word power(Word x, Word n) {
    Word r=1;
    for (; n; n>>=1, x=mul(x,x)) if (n&1) r=mul(r,x);
    return r;
}
inline Word eval(const Words& coeffs, Word x) {
    Word result=0;
    for (auto it=coeffs.rbegin(); it!=coeffs.rend(); ++it) result=add(mul(result,x),*it);
    return result;
}
inline Word dot(const Words& x, const Words& y) {
    need(x.size()==y.size(),"dot dimension");
    Word z=0;
    for (size_t i=0;i<x.size();++i) z=add(z,mul(x[i],y[i]));
    return z;
}
inline Word get(const unsigned char* b, unsigned n=8) {
    Word x=0;
    for (unsigned j=0;j<n;++j) x|=Word(b[j])<<(8*j);
    return x;
}
inline void put(unsigned char* b, Word x) {
    for (unsigned j=0;j<8;++j) b[j]=static_cast<unsigned char>(x>>(8*j));
}
inline void append(Bytes& b, Word x) { size_t at=b.size(); b.resize(at+8); put(b.data()+at,x); }
template<class T> void append_bytes(Bytes& b, const T& data) { b.insert(b.end(), data.begin(),data.end()); }
inline void append_words(Bytes& b, const Words& v) { for (Word x:v) append(b,x); }
struct Reader {
    const Bytes& bytes;
    size_t at=0;
    const unsigned char* take(size_t n) {
        need(n<=bytes.size()-at,"truncated input");
        const auto* p=bytes.data()+at;
        at+=n;
        return p;
    }
    unsigned u32() { return unsigned(get(take(4),4)); }
    Word field() { Word x=get(take(8)); need(x<P,"noncanonical field"); return x; }
    Words words(size_t n) { Words out(n); for (Word& x:out) x=field(); return out; }
    Digest digest() { Digest out; std::memcpy(out.data(),take(64),64); return out; }
    void end() const { need(at==bytes.size(),"trailing input"); }
};

struct Domain {
    Word root=power(7,(P-1)/N);
    Words omega, canonical;
    Domain() {
        need(power(root,N/2)==P-1 && power(7,N)!=1,"invalid registered domain");
        Word w=7;
        for (unsigned i=0;i<S;++i,w=mul(w,root)) omega.push_back(w);
        for (unsigned i=0;i<=PolyDegree;++i) canonical.push_back(party(i));
    }
    Word party(unsigned i) const { return power(root,i/K+(N/K)*(i%K)); }
};

inline Words vanish_poly(const Words& grid) {
    Words p{1};
    for (Word x:grid) {
        p.push_back(0);
        for (size_t j=p.size()-1;j>0;--j) p[j]=sub(p[j-1],mul(p[j],x));
        p[0]=sub(0,mul(p[0],x));
    }
    return p;
}

// Lagrange basis in coefficient form for short, repeatedly reused grids.
inline Matrix basis(const Words& grid) {
    Words p=vanish_poly(grid);
    Matrix out;
    for (Word x:grid) {
        Words q(grid.size());
        Word carry=p.back();
        for (size_t j=grid.size(); j>0; --j) {
            q[j-1]=carry;
            carry=add(p[j-1],mul(carry,x));
        }
        Word d=eval(q,x);
        need(d!=0,"duplicate interpolation point");
        Word scale=power(d,P-2);
        for (Word& c:q) c=mul(c,scale);
        out.push_back(std::move(q));
    }
    return out;
}
inline Words coefficients(const Matrix& bs,const Words& values) {
    need(values.size()==bs.size(),"interpolation dimension");
    Words coeff(bs.size());
    for (size_t j=0;j<values.size();++j)
        for (size_t k=0;k<coeff.size();++k) coeff[k]=add(coeff[k],mul(values[j],bs[j][k]));
    return coeff;
}
// Extend an arbitrary evaluation vector to the short canonical verification grid.
// The overlap is large for broadcast tails. Only missing canonical points interpolate.
inline Words reconstruct(const Words& grid,const Words& values,const Words& target) {
    need(grid.size()==values.size(),"broadcast reconstruction dimension");
    std::map<Word,Word> known;
    Words invden(grid.size(),1);
    for (size_t i=0;i<grid.size();++i) {
        need(known.emplace(grid[i],values[i]).second,"duplicate reconstruction point");
        for (size_t j=0;j<i;++j) {
            Word delta=sub(grid[i],grid[j]);
            invden[i]=mul(invden[i],delta);
            invden[j]=mul(invden[j],sub(0,delta));
        }
    }
    for (Word& x:invden) x=power(x,P-2);
    Words result, products(grid.size()+1);
    for (Word x:target) {
        auto it=known.find(x);
        if (it!=known.end()) { result.push_back(it->second); continue; }
        products[0]=1;
        for (size_t i=0;i<grid.size();++i) products[i+1]=mul(products[i],sub(x,grid[i]));
        Word suffix=1, y=0;
        for (size_t i=grid.size();i-->0;) {
            y=add(y,mul(mul(products[i],suffix),mul(invden[i],values[i])));
            suffix=mul(suffix,sub(x,grid[i]));
        }
        result.push_back(y);
    }
    return result;
}
