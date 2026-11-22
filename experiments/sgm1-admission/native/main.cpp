#include "sgm1_verify.h"
#include <cstdint>
#include <fstream>
#include <iostream>
#include <stdexcept>
#include <string>
#include <vector>
namespace {
std::vector<uint8_t> read(const std::string& path,size_t max) {
    std::ifstream f(path,std::ios::binary|std::ios::ate);
    auto n=f.tellg();
    if(!f||n<0||uint64_t(n)>max) throw std::runtime_error("invalid input file size");
    std::vector<uint8_t> b(static_cast<size_t>(n));f.seekg(0);
    if(n&&!f.read(reinterpret_cast<char*>(b.data()),n)) throw std::runtime_error("incomplete file");
    return b;
}
uint8_t digit(char c) {
    if(c>='0'&&c<='9') return c-'0';
    if(c>='a'&&c<='f') return c-'a'+10;
    if(c>='A'&&c<='F') return c-'A'+10;
    throw std::runtime_error("invalid pin");
}
}
int main(int argc,char** argv) {
    try {
        if(argc!=4) throw std::runtime_error("usage: sgm1-verify GENESIS_PIN_HEX STATEMENT_FILE PROOF_FILE");
        std::string hex=argv[1];
        if(hex.size()!=64) throw std::runtime_error("invalid pin length");
        std::vector<uint8_t> pin(32);
        for(size_t i=0;i<pin.size();++i) pin[i]=16*digit(hex[2*i])+digit(hex[2*i+1]);
        auto s=read(argv[2],526),p=read(argv[3],262144);char error[256]{};
        if(!sgm1_verify(pin.data(),pin.size(),s.data(),s.size(),p.data(),p.size(),error,sizeof(error)))
            throw std::runtime_error(error);
        std::cout<<"accepted\n";return 0;
    } catch(const std::exception& e) {std::cerr<<"rejected: "<<e.what()<<'\n';return 1;}
}
