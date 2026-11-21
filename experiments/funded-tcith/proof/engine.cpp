// Complete single-tree fixed-parent SLG1 packed TCitH research registration.
#include "broadcast.hpp"
#include <sys/resource.h>

static unsigned extra(unsigned degree) { return degree+1-S-L; }
static Words first(const Words& a,unsigned n) { return Words(a.begin(),a.begin()+n); }
static std::vector<unsigned> remaining(const Indices& indices,unsigned count) {
    std::vector<unsigned> out;
    for (unsigned i=0;out.size()<count;++i) if (!indices.count(i)) out.push_back(i);
    return out;
}

static Bytes prove(const Domain& domain,const Relation& relation,Hashes& hashes) {
    auto polys=share(domain,relation.slots);
    Commitment commitment(domain,polys,hashes);
    Digest h1=hashes.root(commitment.tree[1]);
    Matrix xi=degree_polys(polys,degree_matrix(hashes,h1));
    Bytes table;
    for (unsigned j=0;j<=D;++j) append_words(table,values_at(xi,domain.canonical[j]));
    Digest h2=hashes.data('X',table);

    Batches batches(domain,relation,hashes,h1,h2);
    Matrix poly(Rho),lin(Rho),secret(Rho);
    for (unsigned j=0;j<=PolyDegree;++j) {
        Word x=domain.canonical[j];
        auto row=values_at(polys,x);
        auto p=batches.nonlinear(row,x);
        for (unsigned r=0;r<Rho;++r) poly[r].push_back(p[r]);
        if (j<=LinearDegree) {
            auto l=batches.linear(row,x);
            for (unsigned r=0;r<Rho;++r) lin[r].push_back(l[r]);
        }
    }
    for (Word w:domain.omega) {
        auto row=values_at(polys,w);
        auto p=batches.nonlinear(row,w),l=batches.linear(row,w);
        for (unsigned r=0;r<Rho;++r) {
            need(p[r]==0,"nonzero polynomial slot");
            secret[r].push_back(l[r]);
        }
    }
    Digest h3=broadcast_digest(hashes,poly,lin);
    Indices indices=challenge(hashes,h1,h2,h3);
    Bytes wire;
    for (const Digest& d:{h1,h2,h3}) append_bytes(wire,d);
    commitment.open(wire,hashes,domain,polys,indices);
    for (Word w:domain.omega) append_words(wire,values_at(xi,w));
    auto other=remaining(indices,extra(PolyDegree));
    for (unsigned r=0;r<Rho;++r) {
        for (unsigned idx:other) append(wire,poly[r][idx]);
        Word sum=0;
        for (Word s:secret[r]) sum=add(sum,s);
        need(sum==batches.batches[r].rhs,"incorrect linear slot sum");
        for (unsigned j=0;j<S-1;++j) append(wire,secret[r][j]);
        for (unsigned j=0;j<extra(LinearDegree);++j) append(wire,lin[r][other[j]]);
    }
    need(wire.size()<=MaxProof,"wire bound exceeded");
    return wire;
}

static void verify(const Domain& domain,const Relation& relation,Hashes& hashes,const Bytes& proof) {
    Reader in{proof};
    Digest h1=in.digest(),h2=in.digest(),h3=in.digest();
    Indices indices=challenge(hashes,h1,h2,h3);
    Matrix rows=read_openings(in,hashes,indices,h1);
    auto gamma=degree_matrix(hashes,h1);
    Matrix local;
    Words axis;
    for (unsigned index:indices) axis.push_back(domain.party(index));
    axis.insert(axis.end(),domain.omega.begin(),domain.omega.end());
    for (const auto& row:rows) local.push_back(local_xi(row,gamma));
    for (unsigned j=0;j<S;++j) local.push_back(in.words(Eta));
    Matrix xi;
    auto target=first(domain.canonical,D+1);
    for (unsigned r=0;r<Eta;++r) {
        Words column;
        for (const auto& row:local) column.push_back(row[r]);
        xi.push_back(reconstruct(axis,column,target));
    }
    Bytes table;
    for (unsigned j=0;j<=D;++j)
        for (unsigned r=0;r<Eta;++r) append(table,xi[r][j]);
    need(hashes.data('X',table)==h2,"degree broadcast mismatch");
    Batches batches(domain,relation,hashes,h1,h2);
    Matrix poly(Rho),lin(Rho);
    for (unsigned j=0;j<L;++j) {
        auto p=batches.nonlinear(rows[j],axis[j]), l=batches.linear(rows[j],axis[j]);
        for (unsigned r=0;r<Rho;++r) { poly[r].push_back(p[r]); lin[r].push_back(l[r]); }
    }
    auto other=remaining(indices,extra(PolyDegree));
    Words pgrid=axis,lgrid=axis;
    for (unsigned j=0;j<other.size();++j) {
        Word x=domain.canonical[other[j]];
        pgrid.push_back(x);
        if (j<extra(LinearDegree)) lgrid.push_back(x);
    }
    for (unsigned r=0;r<Rho;++r) {
        poly[r].resize(L+S,0);
        for (unsigned j=0;j<extra(PolyDegree);++j) poly[r].push_back(in.field());
        Word last=batches.batches[r].rhs;
        for (unsigned j=0;j<S-1;++j) {
            Word v=in.field(); last=sub(last,v); lin[r].push_back(v);
        }
        lin[r].push_back(last);
        for (unsigned j=0;j<extra(LinearDegree);++j) lin[r].push_back(in.field());
        poly[r]=reconstruct(pgrid,poly[r],domain.canonical);
        lin[r]=reconstruct(lgrid,lin[r],first(domain.canonical,LinearDegree+1));
    }
    in.end();
    need(broadcast_digest(hashes,poly,lin)==h3,"monetary broadcast mismatch");
}

static Bytes read_bounded(std::istream& input,size_t limit) {
    Bytes buf(limit+1);
    input.read(reinterpret_cast<char*>(buf.data()),buf.size());
    need(!input.bad() && input.eof() && size_t(input.gcount())<=limit,"oversized or unreadable input");
    buf.resize(input.gcount());
    return buf;
}

int main(int argc,char** argv) try {
    need(argc==3,"usage: tcith prove|verify REGISTERED_SHAPE");
    bool prover=std::string(argv[1])=="prove";
    need(prover||std::string(argv[1])=="verify","unknown role");
    struct rlimit core{0,0};
    need(setrlimit(RLIMIT_CORE,&core)==0,"core dump control unavailable");
    std::ifstream source(argv[2],std::ios::binary);
    need(bool(source),"public registered shape unavailable");
    auto program=read_bounded(source,3717289);
    Bytes id(32);
    need(EVP_Digest(program.data(),program.size(),id.data(),nullptr,EVP_sha256(),nullptr)==1,"shape hash");
    constexpr char hex[]="0123456789abcdef";
    std::string digest;
    for (auto c:id) { digest+=hex[c>>4]; digest+=hex[c&15]; }
    need(digest==ShapeHex,"unregistered verifier program");

    auto request=read_bounded(std::cin,336+(prover?Private*8:MaxProof));
    Reader in{request};
    in.take(32);
    auto pub=in.words(Public);
    Hashes hashes(Bytes(request.begin(),request.begin()+in.at),id);
    Domain domain;
    if (prover) {
        auto w=in.words(Private); in.end();
        Relation relation(program,pub,&w);
        auto proof=prove(domain,relation,hashes);
        std::cout.write(reinterpret_cast<const char*>(proof.data()),proof.size());
        need(std::cout.good(),"proof output failed");
    } else {
        Relation relation(program,pub,nullptr);
        verify(domain,relation,hashes,Bytes(request.begin()+in.at,request.end()));
    }
    return 0;
} catch (const std::exception& error) {
    std::cerr << error.what() << "\n";
    return 1;
}
