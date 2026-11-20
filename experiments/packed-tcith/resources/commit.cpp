// The TCitH-MT commitment and masked degree-check kernel for one SLG1 shape.
// All polynomial coefficients and salts are public deterministic test data.
#include <openssl/evp.h>
#include <algorithm>
#include <array>
#include <chrono>
#include <cstdint>
#include <cstring>
#include <fstream>
#include <iostream>
#include <memory>
#include <map>
#include <iterator>
#include <set>
#include <stdexcept>
#include <vector>

using Word = std::uint64_t;
using Digest = std::array<unsigned char, 64>;
using Bytes = std::vector<unsigned char>;
constexpr Word P = 0xffffffff00000001ULL;
constexpr unsigned N = 1u << 20, K = 128, Cosets = N / K;
constexpr unsigned Coeffs = 126, Open = 25, Inputs = 661 + 50, Masks = 33;
constexpr unsigned Width = Inputs + Masks;
using Poly = std::array<Word, Coeffs>;

Word mul(Word x, Word y) { return static_cast<Word>((__uint128_t(x) * y) % P); }
Word add(Word x, Word y) { Word z = x + y; return z < x || z >= P ? z - P : z; }
Word sub(Word x, Word y) { return x >= y ? x - y : P - (y - x); }
Word power(Word x, Word n) {
    Word r = 1;
    for (; n; n >>= 1, x = mul(x, x)) if (n & 1) r = mul(r, x);
    return r;
}
void put(unsigned char* out, Word x) {
    for (unsigned k = 0; k < 8; ++k) out[k] = static_cast<unsigned char>(x >> (8 * k));
}
Word get(const unsigned char* in) {
    Word value = 0;
    for (unsigned k = 0; k < 8; ++k) value |= Word(in[k]) << (8 * k);
    return value;
}
using Context = std::unique_ptr<EVP_MD_CTX, decltype(&EVP_MD_CTX_free)>;
Context context() {
    Context out(EVP_MD_CTX_new(), EVP_MD_CTX_free);
    if (!out) throw std::runtime_error("EVP context");
    return out;
}
void check(int ok) { if (ok != 1) throw std::runtime_error("OpenSSL digest failure"); }
Digest hash(EVP_MD_CTX* ctx, const void* bytes, std::size_t length) {
    Digest out{};
    check(EVP_DigestInit_ex(ctx, EVP_sha3_512(), nullptr));
    check(EVP_DigestUpdate(ctx, bytes, length));
    check(EVP_DigestFinal_ex(ctx, out.data(), nullptr));
    return out;
}
Bytes xof(unsigned char domain, const Bytes& data, std::size_t length) {
    Bytes out(length);
    auto ctx = context();
    check(EVP_DigestInit_ex(ctx.get(), EVP_shake256(), nullptr));
    check(EVP_DigestUpdate(ctx.get(), &domain, 1));
    check(EVP_DigestUpdate(ctx.get(), data.data(), data.size()));
    check(EVP_DigestFinalXOF(ctx.get(), out.data(), length));
    return out;
}
std::vector<Word> fields(unsigned char domain, const Bytes& seed, std::size_t count) {
    auto bytes = xof(domain, seed, (count + 64) * 8);
    std::vector<Word> out;
    out.reserve(count);
    for (std::size_t i = 0; i < bytes.size(); i += 8) {
        auto v = get(&bytes[i]);
        if (v < P) out.push_back(v);
        if (out.size() == count) return out;
    }
    throw std::runtime_error("test vector exhausted");
}
Word eval(const Poly& poly, Word x) {
    Word y = 0;
    for (auto i = poly.rbegin(); i != poly.rend(); ++i) y = add(mul(y, x), *i);
    return y;
}
struct CosetTransform {
    std::array<unsigned, K> reversed{};
    std::array<Word, K> factors{};
    explicit CosetTransform(Word root) {
        for (unsigned j = 1; j < K; ++j) reversed[j] = (reversed[j / 2] / 2) + (j & 1) * (K / 2);
        for (unsigned h = 1; h < K; h *= 2) {
            Word step = power(root, K / (2 * h));
            factors[h] = 1;
            for (unsigned k = 1; k < h; ++k) factors[h+k] = mul(factors[h+k-1], step);
        }
    }
    void values(const Poly& c, const std::array<Word, K>& scale, Word* a) const {
        for (unsigned k = 0; k < K; ++k) a[reversed[k]] = k < Coeffs ? mul(c[k], scale[k]) : 0;
        for (unsigned h = 1; h < K; h *= 2) {
            for (unsigned i = 0; i < K; i += 2 * h) {
                for (unsigned j = 0; j < h; ++j) {
                    Word u = a[i+j], v = mul(a[i+j+h], factors[h+j]);
                    a[i+j] = add(u,v);
                    a[i+j+h] = sub(u,v);
                }
            }
        }
    }
};

// Same component from public bytes in a new process. A separate Python reader
// checks it independently; both stop before the two monetary broadcasts.
void verify_component(const Bytes& bytes) {
    auto ctx=context();
    std::size_t off=0;
    auto read=[&](std::size_t n) {
        if (n>bytes.size()-off) throw std::runtime_error("truncated");
        const unsigned char* part=bytes.data()+off;
        off+=n;
        return part;
    };
    const auto* root_hash=read(64);
    Bytes seed(root_hash,root_hash+64);
    auto gamma=fields('G',seed,Masks*Inputs);
    const unsigned mbytes=8*Coeffs*Masks;
    const auto* table=read(mbytes);
    Bytes masked(1+mbytes,'D');
    std::memcpy(masked.data()+1,table,mbytes);
    auto binding=hash(ctx.get(),masked.data(),masked.size());
    seed.insert(seed.end(),binding.begin(),binding.end());
    std::array<Poly,Masks> xi;
    for (unsigned i=0; i<Masks; ++i) for (unsigned k=0; k<Coeffs; ++k) {
        xi[i][k]=get(table+8*(i*Coeffs+k));
        if (xi[i][k]>=P) throw std::runtime_error("noncanonical degree coefficient");
    }
    auto draws=xof('I',seed,1024);
    std::set<unsigned> selected;
    for (unsigned j=0;j<draws.size() && selected.size()<Open;j+=8) selected.insert(get(&draws[j]) & (N-1));
    if (selected.size()!=Open) throw std::runtime_error("challenge exhausted");
    std::map<unsigned,Digest> active;
    const Word omega=power(7,(P-1)/N);
    for (unsigned i:selected) {
        Bytes leaf(1+32+8*Width,'L');
        std::memcpy(leaf.data()+1,read(leaf.size()-1),leaf.size()-1);
        active[N+i]=hash(ctx.get(),leaf.data(),leaf.size());
        std::array<Word,Width> q;
        for (unsigned j=0; j<Width; ++j) {
            q[j]=get(leaf.data()+33+8*j);
            if (q[j]>=P) throw std::runtime_error("noncanonical share");
        }
        Word x=power(omega,i/K + Cosets*(i%K));
        for (unsigned m=0; m<Masks; ++m) {
            Word rhs=q[Inputs+m];
            for (unsigned j=0; j<Inputs; ++j) rhs=add(rhs,mul(gamma[m*Inputs+j],q[j]));
            if (rhs!=eval(xi[m],x)) throw std::runtime_error("masked degree opening mismatch");
        }
    }
    while (!active.count(1)) {
        std::map<unsigned,Digest> parents;
        for (auto& [i,own]:active) {
            if (parents.count(i/2)) continue;
            auto it=active.find(i^1);
            auto other=it==active.end() ? read(64) : it->second.data();
            std::array<unsigned char,129> node{'N'};
            std::memcpy(&node[1],i%2 ? other : own.data(),64);
            std::memcpy(&node[65],i%2 ? own.data() : other,64);
            parents[i/2]=hash(ctx.get(),node.data(),node.size());
        }
        active.swap(parents);
    }
    if (off!=bytes.size() || std::memcmp(active.at(1).data(),root_hash,64)!=0)
        throw std::runtime_error("Merkle root mismatch or trailing data");
}

int main(int argc, char** argv) try {
    if (argc==3 && std::string(argv[1])=="--verify") {
        std::ifstream in(argv[2],std::ios::binary);
        if (!in) throw std::runtime_error("component input unavailable");
        Bytes bytes((std::istreambuf_iterator<char>(in)),std::istreambuf_iterator<char>());
        verify_component(bytes);
        for (unsigned i=0; i<5; ++i) {
            auto t=std::chrono::steady_clock::now();
            verify_component(bytes);
            std::cout << std::chrono::duration<double>(std::chrono::steady_clock::now()-t).count() << "\n";
        }
        return 0;
    }
    if (argc != 2) throw std::runtime_error("pass output path for the public kernel transcript");
    const Word root = power(7, (P - 1) / N), small = power(root, Cosets);
    if (power(root, N/2) != P-1) throw std::runtime_error("invalid subgroup");
    CosetTransform transform(small);
    auto coeffs = fields('C', {}, Width * Coeffs);
    std::vector<Poly> polys(Width);
    for (unsigned j=0; j<Width; ++j) std::copy_n(&coeffs[j*Coeffs], Coeffs, polys[j].begin());
    auto salts = xof('S', {}, 32 * N);
    std::vector<Digest> tree(2 * N);
    auto ctx = context();
    Bytes leaves(K * (1 + 32 + 8 * Width));
    const unsigned stride = leaves.size() / K;
    auto begin = std::chrono::steady_clock::now();
    Word base = 1;
    for (unsigned b=0; b<Cosets; ++b, base=mul(base,root)) {
        std::array<Word, K> scale{1}, values{};
        for (unsigned j=1; j<K; ++j) scale[j] = mul(scale[j-1], base);
        for (unsigned j=0; j<Width; ++j) {
            transform.values(polys[j],scale,values.data());
            for (unsigned i=0; i<K; ++i) put(&leaves[i*stride+33+8*j], values[i]);
        }
        for (unsigned i=0; i<K; ++i) {
            unsigned index = b*K+i;
            auto leaf = &leaves[i*stride];
            leaf[0] = 'L';
            std::memcpy(leaf+1,&salts[32*index],32);
            tree[N+index] = hash(ctx.get(),leaf,stride);
        }
    }
    std::array<unsigned char,129> node{'N'};
    for (unsigned i=N-1; i>0; --i) {
        std::memcpy(&node[1],tree[2*i].data(),64);
        std::memcpy(&node[65],tree[2*i+1].data(),64);
        tree[i] = hash(ctx.get(),node.data(),node.size());
    }
    auto elapsed = std::chrono::duration<double>(std::chrono::steady_clock::now()-begin).count();
    Bytes seed(tree[1].begin(),tree[1].end());
    auto gamma = fields('G',seed,Masks*Inputs);
    Bytes masked(1+8*Masks*Coeffs);
    masked[0]='D';
    for (unsigned m=0; m<Masks; ++m) {
        Poly xi = polys[Inputs+m];
        for (unsigned j=0; j<Inputs; ++j)
            for (unsigned k=0; k<Coeffs; ++k)
                xi[k] = add(xi[k],mul(gamma[m*Inputs+j],polys[j][k]));
        for (unsigned k=0; k<Coeffs; ++k) put(&masked[1+8*(m*Coeffs+k)],xi[k]);
    }
    auto binding = hash(ctx.get(),masked.data(),masked.size());
    seed.insert(seed.end(),binding.begin(),binding.end());
    auto challenges = xof('I',seed,1024);
    std::set<unsigned> active;
    for (unsigned j=0; j<challenges.size() && active.size()<Open; j+=8)
        active.insert(N + (get(&challenges[j]) & (N-1)));
    if (active.size()!=Open) throw std::runtime_error("challenge exhausted");
    std::ofstream out(argv[1],std::ios::binary);
    out.exceptions(std::ios::failbit | std::ios::badbit);
    auto write = [&](const unsigned char* buf, std::size_t size){ out.write(reinterpret_cast<const char*>(buf),size); };
    write(tree[1].data(),64);
    write(masked.data()+1,masked.size()-1);
    for (unsigned index: active) {
        auto i=index-N;
        Word x=mul(power(root,i/K),power(small,i%K));
        Bytes row(1+32+Width*8);
        row[0]='L';
        std::memcpy(row.data()+1,&salts[32*i],32);
        for (unsigned j=0; j<Width; ++j) put(&row[33+8*j],eval(polys[j],x));
        if (hash(ctx.get(),row.data(),row.size()) != tree[index]) throw std::runtime_error("coset/Horner disagreement");
        write(row.data()+1,row.size()-1);
    }
    while (*active.begin()!=1) {
        std::set<unsigned> parents;
        for (unsigned index:active) {
            if (!active.count(index^1)) write(tree[index^1].data(),64);
            parents.insert(index/2);
        }
        active.swap(parents);
    }
    out.close();
    std::cout << "share_table_and_merkle_elapsed_seconds=" << elapsed << "\n";
    return 0;
} catch (const std::exception& exc) {
    std::cerr << exc.what() << "\n";
    return 1;
}
