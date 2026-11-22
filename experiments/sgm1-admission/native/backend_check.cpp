#include "backend.hpp"

#include <fstream>
#include <iostream>
#include <iterator>
#include <stdexcept>

using namespace sgm;
namespace {
Bytes read_file(const char* path) {
    std::ifstream stream(path,std::ios::binary);
    if(!stream) throw std::runtime_error("missing public fixture");
    return Bytes(std::istreambuf_iterator<char>(stream),{});
}
void verify(const Bytes& packet) {
    const std::string name="FS01-ring-paired-projection-test-v1/257+257,2+2";
    Transcript tr(Bytes(name.begin(),name.end()),packet);
    Ring ring(tr,514,4);
    const auto a=tr.challenge("paired-bit weights",257), b=tr.challenge("paired-K weights",2);
    auto c=a, t=b;
    c.insert(c.end(),a.begin(),a.end()); t.insert(t.end(),b.begin(),b.end());
    ring.open(tr,c,t,0);
    tr.finish();
}
K slow(K a,K b) {
    K z;
    for(unsigned i=0;i<256;i++) {
        if((b.limb[i/64]>>(i%64))&1) z^=a;
        auto carry=a.limb[3]>>63;
        for(int j=3;j>0;j--) a.limb[j]=(a.limb[j]<<1)|(a.limb[j-1]>>63);
        a.limb[0]<<=1;
        if(carry) a.limb[0]^=0x425;
    }
    return z;
}
}

int main(int argc,char** argv) {
    try {
        if(argc!=2) throw std::runtime_error("expected public paired projection proof");
        auto packet=read_file(argv[1]);
        auto seed=Bytes{1,2,3}; Transcript tr(seed,packet);
        auto random=tr.challenge("public backend controls",100);
        for(unsigned i=0;i<50;i++) {
            auto a=random[i],b=random[50+i];
            if(a*b!=slow(a,b) || a*inverse(a)!=1) throw std::runtime_error("wide field mismatch");
        }
        for(unsigned i=0;i<65536;i++)
            if(embed(i)*embed(2)!=embed(((i<<1)^((i&0x8000)?0x1100b:0))&0xffff))
                throw std::runtime_error("embedding mismatch");
        verify(packet);
        int rejected=0;
        for(size_t pos: {0UL,128UL,640UL,672UL,8416UL,packet.size()-1,packet.size(),packet.size()+1}) {
            auto altered=packet;
            if(pos<altered.size()) altered[pos]^=1;
            else if(pos==altered.size()) altered.push_back(0);
            else altered.pop_back();
            try { verify(altered); }
            catch(const std::runtime_error&) { rejected++; }
        }
        if(rejected!=8) throw std::runtime_error("accepted altered projection");
        std::cout<<"canonical projection accepted, 8 alterations rejected, 50 wide cross-checks, 65536 embeddings\n";
    } catch(const std::exception& e) { std::cerr<<e.what()<<'\n'; return 1; }
}
