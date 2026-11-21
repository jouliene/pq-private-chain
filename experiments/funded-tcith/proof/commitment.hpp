// Salted commitments and a streaming coset FFT, adapted from packed-tcith/resources/commit.cpp.
#pragma once
#include "field.hpp"
using MdContext=std::unique_ptr<EVP_MD_CTX,decltype(&EVP_MD_CTX_free)>;
struct Hashes {
    MdContext ctx{EVP_MD_CTX_new(),EVP_MD_CTX_free};
    Digest prefix{};
    explicit Hashes(const Bytes& public_input,const Bytes& shape_hash) {
        need(ctx.get() && public_input.size()==336 && shape_hash.size()==32,"invalid transcript prefix");
        const std::string registration="FTL1/TCitH-MT/SLG1/Goldilocks/fixed-parent/fft256/v1";
        Bytes b(registration.begin(),registration.end());
        b.push_back(0);
        append_bytes(b,shape_hash);
        for (unsigned x:{N,K,S,L,D,Rho,Eta,Witness,Hints,Width,7u}) append(b,x);
        append_bytes(b,public_input);
        need(EVP_Digest(b.data(),b.size(),prefix.data(),nullptr,EVP_sha3_512(),nullptr)==1,"prefix hash");
    }
    void start(unsigned char tag,const EVP_MD* md) {
        need(EVP_DigestInit_ex(ctx.get(),md,nullptr)==1 &&
             EVP_DigestUpdate(ctx.get(),&tag,1)==1 &&
             EVP_DigestUpdate(ctx.get(),prefix.data(),prefix.size())==1,"hash initialize");
    }
    void feed(const unsigned char* p,size_t n) {
        need(EVP_DigestUpdate(ctx.get(),p,n)==1,"hash update");
    }
    Digest finish() {
        Digest d;
        need(EVP_DigestFinal_ex(ctx.get(),d.data(),nullptr)==1,"hash final");
        return d;
    }
    Digest data(unsigned char tag,const Bytes& b) {
        start(tag,EVP_sha3_512());
        feed(b.data(),b.size());
        return finish();
    }
    Digest leaf(unsigned idx,const unsigned char* salt_and_words) {
        unsigned char pos[8]; put(pos,idx);
        start('L',EVP_sha3_512()); feed(pos,8); feed(salt_and_words,32+8*Width);
        return finish();
    }
    Digest node(unsigned idx,const Digest& a,const Digest& b) {
        unsigned char pos[8]; put(pos,idx);
        start('N',EVP_sha3_512()); feed(pos,8); feed(a.data(),64); feed(b.data(),64);
        return finish();
    }
    Digest root(const Digest& tree_root) {
        start('R',EVP_sha3_512()); feed(tree_root.data(),64); return finish();
    }
};
struct Stream {
    Hashes& hashes;
    unsigned char tag;
    Bytes seed;
    std::array<unsigned char,4096> block{};
    size_t offset=block.size();
    Word counter=0;
    Stream(Hashes& h,unsigned char t,std::initializer_list<Digest> prior):hashes(h),tag(t) {
        for (const Digest& d:prior) append_bytes(seed,d);
    }
    Word raw() {
        if (offset==block.size()) {
            unsigned char suffix[8]; put(suffix,counter++);
            hashes.start(tag,EVP_shake256());
            hashes.feed(seed.data(),seed.size());
            hashes.feed(suffix,8);
            need(EVP_DigestFinalXOF(hashes.ctx.get(),block.data(),block.size())==1,"challenge XOF");
            offset=0;
        }
        Word x=get(block.data()+offset); offset+=8; return x;
    }
    Word field() { Word x; do { x=raw(); } while (x>=P); return x; }
};
using Indices=std::set<unsigned>;
inline Indices challenge(Hashes& hashes,const Digest& h1,const Digest& h2,const Digest& h3) {
    Stream stream(hashes,'I',{h1,h2,h3});
    Indices indices;
    while (indices.size()<L) indices.insert(unsigned(stream.raw()&(N-1)));
    return indices;
}
inline Bytes random_bytes(size_t n) {
    Bytes b(n);
    need(RAND_priv_bytes(b.data(),int(n))==1,"private randomness unavailable");
    return b;
}
struct RandomWords {
    Bytes buf;
    size_t at=0;
    Word field() {
        while (true) {
            if (at==buf.size()) { buf=random_bytes(8192); at=0; }
            Word x=get(buf.data()+at); at+=8;
            if (x<P) return x;
        }
    }
    Words words(unsigned n) { Words out(n); for (Word& x:out) x=field(); return out; }
};

struct CosetTransform {
    std::array<unsigned,K> reversed{};
    std::array<Word,K> factors{};
    explicit CosetTransform(Word small) {
        for (unsigned j=1;j<K;++j) reversed[j]=reversed[j/2]/2+(j&1)*(K/2);
        for (unsigned h=1;h<K;h*=2) {
            Word step=power(small,K/(2*h));
            factors[h]=1;
            for (unsigned j=1;j<h;++j) factors[h+j]=mul(factors[h+j-1],step);
        }
    }
    void values(const Words& coeff,const std::array<Word,K>& scale,std::array<Word,K>& a) const {
        for (unsigned k=0;k<K;++k) a[reversed[k]]=k<coeff.size()?mul(coeff[k],scale[k]):0;
        for (unsigned h=1;h<K;h*=2)
            for (unsigned i=0;i<K;i+=2*h)
                for (unsigned j=0;j<h;++j) {
                    Word u=a[i+j],v=mul(a[i+j+h],factors[h+j]);
                    a[i+j]=add(u,v); a[i+j+h]=sub(u,v);
                }
    }
};
struct Commitment {
    Bytes salts=random_bytes(32*N);
    std::vector<Digest> tree=std::vector<Digest>(2*N);
    Commitment(const Domain& domain,const Matrix& polys,Hashes& hashes) {
        const unsigned stride=32+Width*8;
        Bytes tile(K*stride);
        CosetTransform fft(power(domain.root,N/K));
        Word base=1;
        for (unsigned coset=0;coset<N/K;++coset,base=mul(base,domain.root)) {
            std::array<Word,K> scale{1},vals;
            for (unsigned k=1;k<K;++k) scale[k]=mul(scale[k-1],base);
            for (unsigned j=0;j<Width;++j) {
                fft.values(polys[j],scale,vals);
                for (unsigned k=0;k<K;++k) put(tile.data()+k*stride+32+8*j,vals[k]);
            }
            for (unsigned k=0;k<K;++k) {
                unsigned index=coset*K+k;
                auto leaf=tile.data()+k*stride;
                std::memcpy(leaf,salts.data()+32*index,32);
                tree[N+index]=hashes.leaf(index,leaf);
            }
        }
        for (unsigned i=N-1;i>0;--i) tree[i]=hashes.node(i,tree[2*i],tree[2*i+1]);
    }
    void open(Bytes& b,Hashes& hashes,const Domain& domain,const Matrix& polys,const Indices& indices) const {
        Indices active;
        for (unsigned index:indices) {
            size_t offset=b.size();
            b.insert(b.end(),salts.begin()+32*index,salts.begin()+32*(index+1));
            Word x=domain.party(index);
            for (const Words& p:polys) append(b,eval(p,x));
            need(hashes.leaf(index,b.data()+offset)==tree[N+index],"coset and Horner disagree");
            active.insert(N+index);
        }
        while (*active.begin()!=1) {
            Indices parents;
            for (unsigned i:active) {
                if (!active.count(i^1)) append_bytes(b,tree[i^1]);
                parents.insert(i/2);
            }
            active.swap(parents);
        }
    }
};
inline Matrix read_openings(Reader& in,Hashes& hashes,const Indices& indices,const Digest& h1) {
    std::map<unsigned,Digest> active;
    Matrix rows;
    for (unsigned index:indices) {
        const auto* leaf=in.take(32);
        rows.push_back(in.words(Width));
        active[N+index]=hashes.leaf(index,leaf);
    }
    while (active.begin()->first!=1) {
        std::map<unsigned,Digest> parents;
        for (const auto& entry:active) {
            unsigned i=entry.first;
            if (parents.count(i/2)) continue;
            auto other=active.find(i^1);
            Digest sib=other==active.end()?in.digest():other->second;
            parents[i/2]=i%2 ? hashes.node(i/2,sib,entry.second) : hashes.node(i/2,entry.second,sib);
        }
        active.swap(parents);
    }
    need(hashes.root(active.at(1))==h1,"commitment root mismatch");
    return rows;
}
