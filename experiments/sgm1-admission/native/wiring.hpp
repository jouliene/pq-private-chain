#pragma once
#include <array>
#include <cstddef>
#include <cstdint>
#include <vector>

namespace sgm {
using IDs = std::vector<uint32_t>;
struct Equation { std::vector<IDs> terms; IDs target; };
struct Selector { IDs child, sibling, left; uint32_t direction; };
struct Setup {
    uint32_t width=2;
    std::vector<Equation> linear;
    std::array<IDs,3> scalar;
    std::vector<Selector> selectors;
    std::vector<std::array<IDs,5>> boundary;
    explicit Setup(const std::vector<uint8_t>& statement);
private:
    IDs alloc(size_t), xor2(const IDs&,const IDs&), product(const IDs&,const IDs&);
    IDs nonzero(IDs), gate(const IDs&,const IDs&), add(IDs,IDs);
    IDs permute(IDs), shake(uint8_t,const std::vector<IDs>&);
    void equal(const IDs&,const IDs&), pin(const IDs&,IDs), below(const IDs&,uint64_t);
};
}
