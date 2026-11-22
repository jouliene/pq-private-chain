// Test-only complete public wiring digest. The verifier never accepts these digests as inputs.
#include "wiring.hpp"
#include <openssl/evp.h>
#include <array>
#include <fstream>
#include <iostream>
#include <iterator>
#include <stdexcept>
using namespace sgm;
namespace {
struct Digest {
    EVP_MD_CTX* ctx=EVP_MD_CTX_new();
    Digest() {if(!ctx||EVP_DigestInit_ex(ctx,EVP_sha256(),nullptr)!=1) throw std::runtime_error("SHA256 init");}
    ~Digest() {EVP_MD_CTX_free(ctx);}
    void word(uint32_t x) {
        uint8_t b[4]={uint8_t(x),uint8_t(x>>8),uint8_t(x>>16),uint8_t(x>>24)};
        if(EVP_DigestUpdate(ctx,b,4)!=1) throw std::runtime_error("SHA256 update");
    }
    void vec(const IDs& v) {
        word(v.size());
        // Host is x86_64, each ID is a little-endian uint32.
        if(EVP_DigestUpdate(ctx,v.data(),4*v.size())!=1) throw std::runtime_error("SHA256 vector");
    }
    void print() {
        std::array<uint8_t,32> d{};unsigned n=0;
        if(EVP_DigestFinal_ex(ctx,d.data(),&n)!=1||n!=32) throw std::runtime_error("SHA256 final");
        for(auto x:d) std::printf("%02x",x);
        std::puts("");
    }
};
}
int main(int argc,char** argv) {
    if(argc!=2) return 2;
    std::ifstream f(argv[1],std::ios::binary);
    std::vector<uint8_t> data((std::istreambuf_iterator<char>(f)),{});
    Setup w(data);Digest h;h.word(w.width);h.word(w.boundary.size());
    for(const auto& p:w.boundary) for(const auto& b:p) h.vec(b);
    h.word(w.selectors.size());
    for(const auto& s:w.selectors) {h.vec(s.child);h.vec(s.sibling);h.word(s.direction);h.vec(s.left);}
    for(const auto& v:w.scalar) h.vec(v);
    h.word(w.linear.size());
    for(const auto& l:w.linear) {h.word(l.terms.size());for(const auto& v:l.terms) h.vec(v);h.vec(l.target);}
    h.print();
}
