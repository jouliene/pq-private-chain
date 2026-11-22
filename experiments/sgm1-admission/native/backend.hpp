#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <string_view>
#include <vector>
#include <immintrin.h>

namespace sgm {

using Bytes = std::vector<std::uint8_t>;
using F = std::uint16_t;

// Canonical polynomial-basis element, four little-endian limbs.
struct K {
    std::uint64_t limb[4];
    constexpr K(std::uint64_t low=0) : limb{low,0,0,0} {}
    K& operator^=(const K& b) {
        for (int i=0; i<4; ++i) limb[i] ^= b.limb[i];
        return *this;
    }
    friend K operator^(K a, const K& b) { return a ^= b; }
    friend bool operator==(const K& a,const K& b) = default;
};

namespace detail {
struct Double { __m128i low, high; };
inline Double carryless128(__m128i a,__m128i b) {
    auto low = _mm_clmulepi64_si128(a,b,0);
    auto high = _mm_clmulepi64_si128(a,b,0x11);
    auto ax = a ^ _mm_shuffle_epi32(a,0x4e);
    auto bx = b ^ _mm_shuffle_epi32(b,0x4e);
    auto cross = _mm_clmulepi64_si128(ax,bx,0) ^ low ^ high;
    return {low ^ _mm_slli_si128(cross,8),high ^ _mm_srli_si128(cross,8)};
}
}

inline K operator*(const K& a,const K& b) {
    const auto* aa = reinterpret_cast<const __m128i*>(a.limb);
    const auto* bb = reinterpret_cast<const __m128i*>(b.limb);
    auto al=_mm_loadu_si128(aa), ah=_mm_loadu_si128(aa+1);
    auto bl=_mm_loadu_si128(bb), bh=_mm_loadu_si128(bb+1);
    auto lo=detail::carryless128(al,bl), hi=detail::carryless128(ah,bh);
    auto cross=detail::carryless128(al^ah,bl^bh);
    auto c0=lo.low, c1=lo.high^cross.low^lo.low^hi.low;
    auto c2=hi.low^cross.high^lo.high^hi.high, c3=hi.high;
    const auto poly = _mm_set_epi64x(0,0x425);
    // X^256 = X^10+X^5+X^2+1. Fold high limbs, then the last <=10 high bits.
    auto r0=_mm_clmulepi64_si128(c2,poly,0), r1=_mm_clmulepi64_si128(c2,poly,1);
    auto r2=_mm_clmulepi64_si128(c3,poly,0), r3=_mm_clmulepi64_si128(c3,poly,1);
    c0 ^= r0 ^ _mm_slli_si128(r1,8) ^ _mm_clmulepi64_si128(r3,poly,1);
    c1 ^= _mm_srli_si128(r1,8) ^ r2 ^ _mm_slli_si128(r3,8);
    K out;
    _mm_storeu_si128(reinterpret_cast<__m128i*>(out.limb),c0);
    _mm_storeu_si128(reinterpret_cast<__m128i*>(out.limb+2),c1);
    return out;
}

K inverse(K a);
K embed(F a);
using Digest = std::array<std::uint8_t,64>;

class Transcript {
public:
    Transcript(const Bytes& statement,const Bytes& packet);
    Bytes message(std::string_view label,std::size_t length);
    std::vector<K> fields(std::string_view label,std::size_t count);
    std::vector<K> challenge(std::string_view label,std::size_t count);
    void finish() const;
    std::size_t position() const { return pos_; }
private:
    const Bytes& packet_;
    std::size_t pos_ = 0;
    Digest state_;
};

class Ring {
public:
    Ring(Transcript& tr,std::size_t nbits,std::size_t ntrace);
    void open(Transcript& tr,const std::vector<K>& coef,const std::vector<K>& tracecoef,K rhs);
private:
    std::size_t nbits_,ntrace_,rows_;
    Bytes root_,digest_;
    std::vector<F> gamma_;
    bool opened_ = false;
};

}
