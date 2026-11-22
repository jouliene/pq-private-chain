// Public verifier for the fixed SGM1 99-permutation structured Keccak/Compiler 1 relation.
#include "sgm1_verify.h"
#include "backend.hpp"
#include "wiring.hpp"
#include <algorithm>
#include <array>
#include <bit>
#include <cstdio>
#include <functional>
#include <numeric>
#include <stdexcept>
#include <string>
#include <utility>

namespace sgm {
namespace {
using V=std::vector<K>;
using Form=V;
using Bind=std::function<void(V&,K)>;
constexpr unsigned N=1600, pad=2048, flatten=4, depth=6;
unsigned ell(size_t n) {return std::bit_width(n-1);}
V eq_table(const V& point) {
    V out(1<<point.size()); out[0]=1;
    size_t n=1;
    for(auto r:point) {
        for(size_t i=0;i<n;++i) {K v=out[i]*r;out[i]^=v;out[n+i]=v;}
        n*=2;
    }
    return out;
}
K eq_value(const V& a,const V& b) {
    K v=1;
    for(size_t i=0;i<a.size();++i) v=v*(K(1)^a[i]^b[i]);
    return v;
}
void axpy(V& dest,const V& src,K k) {
    for(size_t i=0;i<src.size();++i) if(src[i]!=0) dest[i]^=src[i]*k;
}
K dot(const V& a,const V& b) {
    K v=0;for(size_t i=0;i<a.size();++i) v^=a[i]*b[i];return v;
}
V series(unsigned first,unsigned count) {
    V nodes(count);for(unsigned i=0;i<count;++i) nodes[i]=first+i;return nodes;
}
V lagrange(const V& nodes,K x) {
    V b(nodes.size());
    for(size_t i=0;i<nodes.size();++i) {
        K n=1,d=1;
        for(size_t j=0;j<nodes.size();++j) if(j!=i) {
            n=n*(x^nodes[j]);d=d*(nodes[i]^nodes[j]);
        }
        b[i]=n*inverse(d);
    }
    return b;
}
V mix(const std::vector<V>& forms,const V& weights) {
    V v(forms[0].size());for(size_t i=0;i<forms.size();++i) axpy(v,forms[i],weights[i]);return v;
}
struct Maps {
    std::array<std::array<uint16_t,11>,N> theta{};
    std::array<std::array<uint16_t,N>,3> indices{};
    std::array<uint64_t,24> rc{};
    Maps() {
        constexpr int rot[]={0,1,62,28,27,36,44,6,55,20,3,10,43,25,39,41,45,15,21,8,18,2,61,56,14};
        for(unsigned y=0;y<5;++y) for(unsigned x=0;x<5;++x) for(unsigned z=0;z<64;++z) {
            unsigned lane=x+5*y,target=y+5*((2*x+3*y)%5);
            auto& a=theta[target*64+(z+rot[lane])%64];
            a[0]=lane*64+z;
            for(unsigned j=0;j<5;++j) {
                a[j+1]=64*((x+4)%5+5*j)+z;
                a[j+6]=64*((x+1)%5+5*j)+(z+63)%64;
            }
            for(unsigned k=0;k<3;++k) indices[k][lane*64+z]=64*((x+k)%5+5*y)+z;
        }
        uint8_t v=1;
        for(auto& round:rc) for(unsigned j=0;j<7;++j) {
            if(v&1) round|=uint64_t(1)<<((1<<j)-1);
            v=uint8_t((v<<1)^((v&128)?0x71:0));
        }
    }
};
const Maps& maps() {static const Maps m;return m;}
std::vector<V> map_weights(const V& wx) {
    const auto& m=maps();
    std::vector<V> w(3,V(pad));
    for(unsigned k=0;k<3;++k) for(unsigned i=0;i<N;++i)
        for(auto j:m.theta[m.indices[k][i]]) w[k][j]^=wx[i];
    return w;
}
void state_project(const Setup& w,bool output,const V& wx,const V& wz,K scale,V& coeff) {
    size_t z=0;
    for(const auto& permutation:w.boundary) for(unsigned k=0;k<flatten;++k,++z) {
        auto& ids=permutation[k+(output?1:0)];
        K v=wz[z]*scale;
        for(unsigned i=0;i<N;++i) coeff[ids[i]]^=wx[i]*v;
    }
}

class Verifier {
    Transcript& tr;
    const Setup& w;
    const size_t nt;
    size_t cursor=0;
    std::vector<std::pair<Bind,Form>> bindings;
    std::vector<Form> lines;
    std::vector<std::array<Form,3>> products;
    V joint_input=V(pad), input_wz;

    Form fixed(K x=0) const {Form v(nt+1);v[0]=x;return v;}
    std::vector<Form> masked(std::string_view label,size_t count) {
        V fields=tr.fields(label,count);std::vector<Form> f;
        if(cursor+count>nt) throw std::logic_error("trace overflow");
        for(auto x:fields) {auto a=fixed(x);a[++cursor]=1;f.push_back(std::move(a));}
        return f;
    }
    std::pair<Form,V> sc(Form claim,unsigned rounds,unsigned degree,const std::string& label) {
        V r,points=series(0,degree+1);
        for(unsigned i=0;i<rounds;++i) {
            auto m=masked(label,degree);
            K x=tr.challenge(label+" fold",1)[0];r.push_back(x);
            V b=lagrange(points,x);
            // Since g(0)=claim+g(1), the g(1) weight receives both basis terms.
            Form next=fixed(); axpy(next,claim,b[0]);
            for(unsigned j=0;j<degree;++j) axpy(next,m[j],b[j+1]^(j?K(0):b[0]));
            claim=std::move(next);
        }
        return {std::move(claim),std::move(r)};
    }
    void product_check(K e,const Form& left,const Form& right,const Form& extra,const Form& end) {
        auto a=fixed(),c=end; axpy(a,left,e);axpy(c,extra,e);
        products.push_back({std::move(a),right,std::move(c)});
    }
    void rounds() {
        const size_t groups=w.boundary.size()*flatten;
        auto rx=tr.challenge("Keccak output state index",11);
        auto rz=tr.challenge("flattened permutation index",ell(groups));
        auto wx=eq_table(rx),wz=eq_table(rz);
        Form claim=masked("masked output state MLE",1)[0];
        bindings.emplace_back([this,wx,wz](V& out,K k){state_project(w,true,wx,wz,k,out);},claim);
        for(int i=depth-1;i>=0;--i) {
            std::array<K,flatten> rc_values;
            for(unsigned k=0;k<flatten;++k) {
                auto mask=maps().rc[k*depth+i];
                while(mask) {rc_values[k]^=wx[std::countr_zero(mask)]; mask&=mask-1;}
            }
            for(size_t z=0;z<groups;++z) claim[0]^=rc_values[z%flatten]*wz[z];
            auto [end,r]=sc(claim,11+ell(groups),3,"Keccak chi sumcheck");
            V sx(r.begin(),r.begin()+11),sz(r.begin()+11,r.end());
            K e=eq_value(rx,sx)*eq_value(rz,sz);
            auto f=masked("Keccak affine-map MLEs",3);
            Form left=f[1];left[0]^=1;
            product_check(e,left,f[2],f[0],end);
            auto mapped=map_weights(eq_table(sx));wz=eq_table(sz);
            if(!i) {
                input_wz=wz;
                for(unsigned j=0;j<3;++j)
                    bindings.emplace_back([this,m=std::move(mapped[j])](V&,K k){axpy(joint_input,m,k);},f[j]);
                break;
            }
            V scales=tr.challenge("combine Keccak maps",3);
            auto matrix=mix(mapped,scales);
            auto [reduced,prev]=sc(mix(f,scales),11,2,"Keccak linear map sumcheck");
            rx=std::move(prev);rz=std::move(sz);wx=eq_table(rx);
            claim=masked("previous state MLE",1)[0];
            axpy(reduced,claim,dot(matrix,wx));lines.push_back(std::move(reduced));
        }
    }
    void side(const std::string& label,unsigned n,bool selection) {
        auto gamma=tr.challenge(label+" row",n);
        auto [end,r]=sc(fixed(),n,3,label);
        auto f=masked(label+" endpoints",3);K e=eq_value(gamma,r);
        product_check(e,f[0],f[1],f[2],end);
        auto wt=eq_table(r);
        if(!selection) {
            for(size_t j=0;j<3;++j)
                bindings.emplace_back([this,wt,j](V& out,K k){
                    for(size_t i=0;i<w.scalar[j].size();++i) out[w.scalar[j][i]]^=wt[i]*k;
                },f[j]);
            return;
        }
        bindings.emplace_back([this,wt](V& out,K k) {
            size_t offset=0;
            for(const auto& s:w.selectors) {
                K a=0;for(unsigned j=0;j<32;++j) a^=wt[offset++];
                out[s.direction]^=a*k;
            }
        },f[0]);
        for(unsigned j=1;j<=2;++j)
            bindings.emplace_back([this,wt,j](V& out,K scale){
                std::array<K,16> base;
                for(unsigned b=0;b<16;++b) base[b]=embed(1U<<b)*scale;
                size_t offset=0;
                for(const auto& s:w.selectors) {
                    auto& other=j==1?s.sibling:s.left;
                    for(unsigned g=0;g<32;++g) {
                        K v=wt[offset++];
                        for(unsigned b=0;b<16;++b) {
                            unsigned i=16*g+b;K a=v*base[b];
                            out[s.child[i]]^=a;out[other[i]]^=a;
                        }
                    }
                }
            },f[j]);
    }
    void monetary() {
        size_t n=0;
        for(const auto& row:w.linear) n+=row.target.size();
        auto weights=tr.challenge("funded FS01 public and absorb wiring",n);
        K target=0;size_t i=0;
        for(const auto& row:w.linear) for(auto bit:row.target) {if(bit) target^=weights[i];++i;}
        bindings.emplace_back([this,weights=std::move(weights)](V& out,K k) {
            size_t i=0;
            for(const auto& row:w.linear) {
                for(size_t j=0;j<row.target.size();++j) {
                    K x=weights[i++]*k;for(const auto& col:row.terms) out[col[j]]^=x;
                }
            }
        },fixed(target));
    }
public:
    Verifier(Transcript& tr,const Setup& w,size_t nt):tr(tr),w(w),nt(nt){}
    void verify(Ring& ring) {
        rounds();
        side("packed private ordering",5+ell(w.selectors.size()),true);
        side("FS01 scalar predicates",ell(w.scalar[0].size()),false);
        monetary();
        const size_t m=products.size();
        if(cursor+m+1!=nt) throw std::logic_error("registration trace shape");
        auto q=masked("trace quotient",m);++cursor;
        auto nodes=series(1,m),blinded=series(1,m+1);
        K r=1; do {r=tr.challenge("trace quotient point",1)[0];}
            while(std::find(nodes.begin(),nodes.end(),r)!=nodes.end());
        V one=lagrange(blinded,r),two=lagrange(nodes,r);
        auto a=fixed(),b=fixed(),c=fixed(); a[nt]=one.back();
        K z=1;
        for(size_t i=0;i<m;++i) {
            axpy(a,products[i][0],one[i]);axpy(b,products[i][1],two[i]);axpy(c,products[i][2],two[i]);
            z=z*(r^nodes[i]);
        }
        K v=tr.fields("blinded trace evaluation",1)[0];
        a[0]^=v;lines.push_back(std::move(a));
        axpy(c,b,v);axpy(c,mix(q,lagrange(series(m+2,m),r)),z);lines.push_back(std::move(c));
        auto weights=tr.challenge("joint bit and trace equations",bindings.size()+lines.size());
        V out(w.width),trace=fixed();size_t i=0;
        for(auto& [apply,f]:bindings) {apply(out,weights[i]);axpy(trace,f,weights[i++]);}
        state_project(w,false,joint_input,input_wz,1,out);
        for(auto& f:lines) axpy(trace,f,weights[i++]);
        K rhs=trace[0];trace.erase(trace.begin());
        ring.open(tr,out,trace,rhs);
    }
};

void check(const Bytes& pin,const Bytes& statement,const Bytes& proof) {
    Setup w(statement);
    const unsigned outer=11+ell(w.boundary.size()*flatten);
    const unsigned trace=1+depth*(3*outer+3)+(depth-1)*23+3*(5+ell(w.selectors.size()))+3
                         +3*ell(w.scalar[0].size())+3+depth+3;
    const size_t symbols=(w.width+15)/16+16*trace+544, rows=(symbols+90)/91;
    const size_t expected=120*(rows+32+75)+1920+46080+13650+7744+128+512+32+32*trace;
    if(proof.size()!=expected) throw std::invalid_argument("noncanonical proof length");
    std::string prefix="structured Keccak GKR/C1/v1SGM1/complete-FS01/signed-prefix/v1";
    Bytes domain(prefix.begin(),prefix.end());
    domain.insert(domain.end(),pin.begin(),pin.end());domain.insert(domain.end(),statement.begin(),statement.end());
    domain.push_back(flatten);
    Transcript tr(domain,proof);Ring ring(tr,w.width,trace);
    Verifier(tr,w,trace).verify(ring); tr.finish();
}
}
}

extern "C" int sgm1_verify(const uint8_t* pin,size_t pn,const uint8_t* stmt,size_t sn,
                           const uint8_t* proof,size_t n,char* error,size_t en) noexcept {
    try {
        if(!pin||pn!=32||!stmt||sn!=526||!proof||n==0||n>262144)
            throw std::invalid_argument("invalid registered input lengths");
        sgm::check({pin,pin+pn},{stmt,stmt+sn},{proof,proof+n});
        return 1;
    } catch(const std::exception& e) {
        if(error&&en) std::snprintf(error,en,"%s",e.what());
        return 0;
    } catch(...) {
        if(error&&en) std::snprintf(error,en,"native verification error");
        return 0;
    }
}
