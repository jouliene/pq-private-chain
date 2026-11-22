#include "backend.hpp"

#include <algorithm>
#include <bit>
#include <cstring>
#include <limits>
#include <memory>
#include <numeric>
#include <openssl/evp.h>
#include <span>
#include <stdexcept>
#include <string>

namespace sgm {
namespace {
using View=std::span<const std::uint8_t>;
using namespace std::string_view_literals;
constexpr size_t pack=91, opens=60, leaves=4096, eta=75, degree_n=151, q_n=242;
static_assert(std::endian::native==std::endian::little && sizeof(K)==32);
void require(bool ok,const char* why) { if (!ok) throw std::runtime_error(why); }
View raw(std::string_view s) { return {reinterpret_cast<const uint8_t*>(s.data()),s.size()}; }
template <class T> View bytes(const T& v) {
    return {reinterpret_cast<const uint8_t*>(v.data()),v.size()*sizeof(*v.data())};
}
Bytes le(size_t n,size_t width) {
    Bytes out(width);
    for(size_t i=0;i<width;i++) out[i]=static_cast<uint8_t>(n>>(8*i));
    return out;
}
void absorb(EVP_MD_CTX* ctx,View v) {
    require(EVP_DigestUpdate(ctx,v.data(),v.size())==1,"SHAKE update failed");
}
void framed(EVP_MD_CTX* ctx,View v) {
    uint64_t n=v.size();
    absorb(ctx,{reinterpret_cast<const uint8_t*>(&n),8});
    absorb(ctx,v);
}
void shake(std::span<uint8_t> dest,std::string_view name,std::initializer_list<View> chunks) {
    std::unique_ptr<EVP_MD_CTX,decltype(&EVP_MD_CTX_free)> ctx(EVP_MD_CTX_new(),EVP_MD_CTX_free);
    require(ctx && EVP_DigestInit_ex(ctx.get(),EVP_shake256(),nullptr)==1,"SHAKE initialization failed");
    absorb(ctx.get(),raw("FS01-SmallWoodPlus-C1-R1CS-research-v1\0"sv));
    framed(ctx.get(),raw(name));
    for(auto c:chunks) framed(ctx.get(),c);
    uint8_t unused=0;
    require(EVP_DigestFinalXOF(ctx.get(),dest.empty()?&unused:dest.data(),dest.size())==1,"SHAKE finalization failed");
}
Digest hash(std::string_view name,std::initializer_list<View> chunks) {
    Digest h; shake(h,name,chunks); return h;
}
template<class T> std::vector<T> decode(View v) {
    require(v.size()%sizeof(T)==0,"unaligned field list");
    std::vector<T> out(v.size()/sizeof(T));
    if(!v.empty()) std::memcpy(out.data(),v.data(),v.size());
    return out;
}
K bit(unsigned i) { K a; a.limb[i/64]=uint64_t(1)<<(i%64); return a; }
int degree(const K& a) {
    for(int i=3;i>=0;i--) if(a.limb[i]) return i*64+63-std::countl_zero(a.limb[i]);
    return -1;
}
using ByteTable=std::array<std::array<K,256>,32>;
ByteTable table_from(const std::array<K,256>& images) {
    ByteTable t{};
    for(unsigned i=0;i<32;i++) for(unsigned b=1;b<256;b++)
        t[i][b]=t[i][b&(b-1)] ^ images[8*i+std::countr_zero(b)];
    return t;
}
K map_bits(const ByteTable& table,const K& a) {
    const auto* v=reinterpret_cast<const uint8_t*>(a.limb);
    K r;
    for(unsigned i=0;i<32;i++) r ^= table[i][v[i]];
    return r;
}
K alpha() {
    K x;
    x.limb[0]=0x48aac61ea068d7a5ULL; x.limb[1]=0x7f47feefc2ba73a3ULL;
    x.limb[2]=0x59f58d944fcb6e1cULL; x.limb[3]=0x3002abcf2bc4795dULL;
    return x;
}
struct Tower {
    std::array<K,65536> embedding{};
    std::array<F,131070> exp{};
    std::array<unsigned,65536> log{};
    std::array<F,16> dual{};
    std::array<uint8_t,65536> trace{};
    std::array<K,256> bitsplit{};
    ByteTable decomposition;
    F times(F a,F b) const { return a&&b ? exp[log[a]+log[b]] : 0; }
    F reciprocal(F a) const { require(a!=0,"F inverse zero"); return exp[65535-log[a]]; }
    Tower() {
        uint32_t x=1;
        for(unsigned i=0;i<65535;i++) {
            exp[i]=exp[65535+i]=x; log[x]=i;
            x=(x<<1)^((x&0x8000)?0x1100b:0);
        }
        K monomial=1;
        for(unsigned i=0;i<16;i++,monomial=monomial*alpha())
            for(unsigned j=0;j<(1U<<i);j++) embedding[j|(1U<<i)]=embedding[j]^monomial;
        std::array<K,256> pivots{},codes{};
        for(unsigned j=0;j<256;j++) {
            auto v=bit(j/16)*embedding[1U<<(j%16)], c=bit(j);
            int d=degree(v);
            while(d>=0 && pivots[d]!=0) { v ^= pivots[d]; c ^= codes[d]; d=degree(v); }
            require(d>=0,"F/K basis singular"); pivots[d]=v; codes[d]=c;
        }
        for(unsigned j=0;j<256;j++) {
            K v=bit(j),c;
            for(int d=degree(v);d>=0;d=degree(v)) { v^=pivots[d]; c^=codes[d]; }
            bitsplit[j]=c;
        }
        decomposition=table_from(bitsplit);
        for(unsigned i=0;i<65536;i++) {
            F v=i,h=i;
            for(int j=1;j<16;j++) { v=times(v,v); h^=v; }
            require(h<=1,"absolute trace"); trace[i]=h;
        }
        for(unsigned i=0;i<65536;i++) {
            unsigned v=0;
            for(unsigned j=0;j<16;j++) v|=unsigned(trace[times(i,1U<<j)])<<j;
            if(v && std::has_single_bit(v)) dual[std::countr_zero(v)]=i;
        }
    }
};
const Tower& tower() { static const Tower tables; return tables; }
const K& emb(F a) { return tower().embedding[a]; }
std::vector<F> small_challenge(Transcript& tr,std::string_view label,size_t n) {
    auto wide=tr.challenge(label,(n+15)/16);
    return decode<F>(bytes(wide).first(n*2));
}
std::vector<F> small_message(Transcript& tr,std::string_view label,size_t n) {
    return decode<F>(tr.message(label,2*n));
}
std::vector<F> range(size_t n) {
    std::vector<F> v(n); std::iota(v.begin(),v.end(),0); return v;
}
struct Basis {
    std::vector<F> nodes,inv_den;
    explicit Basis(std::vector<F> xs):nodes(std::move(xs)),inv_den(nodes.size(),1) {
        const auto& f=tower();
        for(size_t i=0;i<nodes.size();i++) {
            for(size_t j=0;j<nodes.size();j++) if(i!=j) inv_den[i]=f.times(inv_den[i],nodes[i]^nodes[j]);
            inv_den[i]=f.reciprocal(inv_den[i]);
        }
    }
    std::vector<F> at(F x) const {
        const auto& f=tower(); std::vector<F> b(nodes.size());
        F prod=1;
        for(size_t i=0;i<nodes.size();i++) {
            if(x==nodes[i]) { b[i]=1; return b; }
            prod=f.times(prod,x^nodes[i]);
        }
        for(size_t i=0;i<nodes.size();i++)
            b[i]=f.times(prod,f.times(inv_den[i],f.reciprocal(x^nodes[i])));
        return b;
    }
};
F fpower(F x,unsigned n) {
    const auto& f=tower(); F y=1;
    while(n) { if(n&1) y=f.times(y,x); x=f.times(x,x); n>>=1; }
    return y;
}
K join(std::span<const F> elements) {
    K out;
    for(unsigned j=0;j<16;j++) out^=bit(j)*emb(elements[j]);
    return out;
}
std::vector<K> ring_weights(const std::vector<K>& coef,const std::vector<K>& trace,
                            std::span<const K> g) {
    const auto& f=tower();
    std::array<K,256> images;
    for(unsigned j=0;j<256;j++) {
        K a;
        for(unsigned l=0;l<4;l++) {
            uint64_t v=f.bitsplit[j].limb[l];
            while(v) { a^=g[64*l+std::countr_zero(v)]; v &= v-1; }
        }
        images[j]=a;
    }
    const auto table=table_from(images);
    std::array<K,16> dual, h{};
    for(unsigned i=0;i<16;i++) dual[i]=emb(f.dual[i]);
    std::vector<K> out((coef.size()+15)/16);
    for(size_t i=0;i<coef.size();i++) if(coef[i]!=0) out[i/16]^=map_bits(table,coef[i])*dual[i%16];
    for(unsigned l=0;l<16;l++) for(unsigned k=0;k<16;k++) h[l]^=g[16*l+k]*dual[k];
    for(const auto& c:trace) for(unsigned j=0;j<16;j++) {
        auto split=map_bits(f.decomposition,c*bit(j)); K z;
        for(unsigned l=0;l<16;l++) {
            F u=static_cast<F>(split.limb[l/4]>>(16*(l%4))); z^=emb(u)*h[l];
        }
        out.push_back(z);
    }
    return out;
}
}
K inverse(K a) {
    require(a!=0,"K inverse zero");
    K t=a;
    // Build a^(2^255-1), then square for the inverse.
    unsigned k=1;
    for(int i=0;i<7;i++) {
        K u=t;
        for(unsigned j=0;j<k;j++) u=u*u;
        t=u*t; t=(t*t)*a; k=2*k+1;
    }
    return t*t;
}
K embed(F a) { return emb(a); }

Transcript::Transcript(const Bytes& statement,const Bytes& packet):packet_(packet),state_(hash("statement",{statement})) {}
Bytes Transcript::message(std::string_view label,size_t length) {
    require(length<=packet_.size()-pos_,"truncated proof");
    View s=View(packet_).subspan(pos_,length); pos_+=length;
    state_=hash("message",{state_,raw(label),s});
    return {s.begin(),s.end()};
}
std::vector<K> Transcript::fields(std::string_view label,size_t count) {
    require(count<=std::numeric_limits<size_t>::max()/32,"field count overflow");
    return decode<K>(message(label,count*32));
}
std::vector<K> Transcript::challenge(std::string_view label,size_t count) {
    require(count<=std::numeric_limits<size_t>::max()/32,"challenge count overflow");
    std::vector<K> out(count);
    auto ptr=reinterpret_cast<uint8_t*>(out.data());
    shake({ptr,32*count},"challenge",{state_,raw(label),le(count,8)});
    state_=hash("continue",{state_,raw(label),bytes(out)});
    return out;
}
void Transcript::finish() const { require(pos_==packet_.size(),"trailing proof bytes"); }

Ring::Ring(Transcript& tr,size_t nbits,size_t ntrace):nbits_(nbits),ntrace_(ntrace) {
    // Geometry belongs to the registered circuit. Bound allocation even for accidental misuse.
    require(nbits<=4000000 && ntrace<=4096,"unsupported ring geometry");
    rows_=((nbits+15)/16+16*ntrace+544+pack-1)/pack;
    std::string id="FS01-ring-trace-AS-v1/F1100b/K-X256+X10+X5+X2+1/beta=1..X^15/";
    auto generator=alpha();
    id.append(reinterpret_cast<const char*>(&generator),32);
    for(auto n:{pack,opens,leaves,eta,size_t(32),size_t(64)}) {
        auto a=le(n,4); id.append(reinterpret_cast<const char*>(a.data()),a.size());
    }
    for(auto n:{nbits,ntrace}) { auto a=le(n,8); id.append(reinterpret_cast<const char*>(a.data()),a.size()); }
    tr.challenge(id,0);
    root_=tr.message("mixed DECS root",64);
    gamma_=small_challenge(tr,"mixed degree matrix",eta*(rows_+32));
    digest_=tr.message("mixed degree digest",64);
}

void Ring::open(Transcript& tr,const std::vector<K>& coef,const std::vector<K>& tracecoef,K rhs) {
    require(!opened_ && coef.size()==nbits_ && tracecoef.size()==ntrace_,"wrong ring vectors"); opened_=true;
    const auto& f=tower();
    auto clear=small_message(tr,"ring masked projections",256);
    auto parts=map_bits(f.decomposition,rhs);
    for(unsigned i=0;i<256;i++)
        require(f.trace[clear[i]]==((parts.limb[i/64]>>(i%64))&1),"ring trace projection rejected");
    auto a=tr.challenge("ring square batch",256);
    K u=tr.fields("ring blinded square projection",1)[0];
    auto scales=tr.challenge("ring authenticate projections and squares",258);
    auto s=scales[256], t=scales[257];
    K target=s*u ^ t*(u*u);
    for(unsigned i=0;i<256;i++) target ^= scales[i]*emb(clear[i]);
    auto q=tr.fields("mixed Q",q_n);
    K qsum;
    for(unsigned i=0;i<pack;i++) qsum^=q[i];
    require(qsum==target,"mixed linear constraints rejected");
    auto weights=ring_weights(coef,tracecoef,scales);
    for(unsigned i=0;i<256;i++) weights.push_back(scales[i] ^ s*a[i]);
    for(unsigned i=0;i<256;i++) weights.push_back(scales[i] ^ t*(a[i]*a[i]));
    for(unsigned i=0;i<16;i++) weights.push_back(s*bit(i));
    for(unsigned i=0;i<16;i++) weights.push_back(t*(bit(i)*bit(i)));
    weights.resize(rows_*pack);

    std::array<bool,leaves> used{};
    std::vector<F> indices;
    while(indices.size()<opens) for(F z:small_challenge(tr,"mixed opening indices",opens)) {
        F i=z%leaves;
        if(!used[i]) { used[i]=true; indices.push_back(i); if(indices.size()==opens) break; }
    }
    std::sort(indices.begin(),indices.end());
    static const Basis basis(range(pack)),qbasis(range(q_n));
    std::vector<F> domain, opened(degree_n*eta);
    for(size_t j=0;j<opens;j++) {
        unsigned i=indices[j]; F x=q_n+i; domain.push_back(x);
        auto data=tr.message("mixed open column",2*(rows_+32+eta));
        auto col=decode<F>(data);
        auto salt=tr.message("mixed salt",32);
        auto leaf=hash("DECS leaf",{le(i,4),data,salt});
        for(unsigned depth=0;depth<12;depth++,i>>=1) {
            auto sibling=tr.message("mixed Merkle sibling",64);
            leaf=i&1 ? hash("DECS node",{sibling,leaf}) : hash("DECS node",{leaf,sibling});
        }
        require(std::equal(leaf.begin(),leaf.end(),root_.begin()),"mixed Merkle opening rejected");
        auto b=basis.at(x), bq=qbasis.at(x);
        K left,right=join(std::span(col).subspan(rows_,16)) ^
                     emb(fpower(x,pack))*join(std::span(col).subspan(rows_+16,16));
        for(unsigned k=0;k<q_n;k++) left ^= q[k]*emb(bq[k]);
        // Sum the weighted witness rows per packing coordinate first. The same
        // embedded column scalar multiplies 91 contiguous K coefficients.
        std::array<K,pack> column_sums{};
        for(size_t r=0;r<rows_;r++) {
            const K scalar=emb(col[r]);
            for(unsigned k=0;k<pack;k++) column_sums[k]^=weights[r*pack+k]*scalar;
        }
        for(unsigned k=0;k<pack;k++) right ^= column_sums[k]*emb(b[k]);
        require(left==right,"mixed Q opening rejected");
        for(size_t row=0;row<eta;row++) {
            F v=col[rows_+32+row];
            for(size_t k=0;k<rows_+32;k++) v^=f.times(gamma_[row*(rows_+32)+k],col[k]);
            opened[j*eta+row]=v;
        }
    }
    for(unsigned i=0;domain.size()<degree_n;i++) if(!used[i]) {
        size_t j=domain.size(); domain.push_back(q_n+i);
        auto extra=small_message(tr,"mixed R completion",eta);
        std::copy(extra.begin(),extra.end(),opened.begin()+j*eta);
    }
    Basis restore(std::move(domain)); std::vector<F> recovered(eta*degree_n);
    for(size_t x=0;x<degree_n;x++) {
        auto b=restore.at(x);
        for(size_t n=0;n<degree_n;n++) for(size_t j=0;j<eta;j++)
            recovered[j*degree_n+x]^=f.times(b[n],opened[n*eta+j]);
    }
    auto digest=hash("mixed R",{bytes(recovered)});
    require(std::equal(digest.begin(),digest.end(),digest_.begin()),"mixed degree check rejected");
}
}
