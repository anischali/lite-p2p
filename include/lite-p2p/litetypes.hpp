#ifndef __LITETYPES_HPP__
#define __LITETYPES_HPP__
#include <cstdint>
#include <string>
#include <algorithm>


template <int _bits> class lite_number {
private:
    uint8_t bytes[(int)(_bits / 8)];


public:

    lite_number() {
        std::memset(bytes, 0x0, sizeof(bytes));
    };

    lite_number(std::initializer_list<uint8_t> other) : lite_number() {
        
        std::copy(std::rbegin(other), std::rend(other), bytes);
    };

     lite_number(std::vector<uint8_t> other) : lite_number() {
        
        std::copy(std::rbegin(other), std::rend(other), bytes);
    };

    lite_number& operator=(const lite_number& other) {
        size_t sz = std::min(sizeof(bytes), sizeof(other.bytes));
            
        std::memcpy(bytes, other.bytes, sz);

        return *this;
    };

    bool operator==(const lite_number& other) const {
        if (sizeof(bytes) != sizeof(other.bytes)) return false;
        return std::memcmp(bytes, other.bytes, sizeof(bytes)) == 0;
    };

    bool operator!=(const lite_number& other) const {
        return !(*this == other);
    };

    lite_number operator&(const lite_number& other) const {
        size_t size = std::min(sizeof(bytes), sizeof(other.bytes));

        lite_number<_bits> result;
        for (size_t i = 0; i < size; ++i) {
            result.bytes[i] = bytes[i] & other.bytes[i];
        }
        return result;
    };

    lite_number operator|(const lite_number& other) const {
        size_t size = std::min(sizeof(bytes), sizeof(other.bytes));

        lite_number<_bits> result;
        for (size_t i = 0; i < size; ++i) {
            result.bytes[i] = bytes[i] | other.bytes[i];
        }
        return result;
    };

    lite_number operator^(const lite_number& other) const {
        size_t size = std::min(sizeof(bytes), sizeof(other.bytes));

        lite_number<_bits> result;
        for (size_t i = 0; i < size; ++i) {
            result.bytes[i] = bytes[i] ^ other.bytes[i];
        }
        return result;
    };

    const size_t bits() {
        return _bits;
    };


    int at(int pos) { 
        return !!(bytes[(int)(pos / 8)] & (1 << (pos % 8))); 
    };


    std::string to_string() {
        char s_hex[6];
        std::string s = "";
        snprintf(s_hex, 6, "0x");
        s += std::string(s_hex);
        for (ssize_t i = sizeof(bytes) - 1; i >= 0; --i) {
            snprintf(s_hex, 6, "%02x", bytes[i]);
            s += std::string(s_hex);
        }

        return s;
    }
};


typedef lite_number<128> uint128_t;
typedef lite_number<256> uint256_t;
typedef lite_number<512> uint512_t;
typedef lite_number<1024> uint1024_t;
typedef lite_number<2048> uint2048_t;
typedef lite_number<4096> uint4096_t;

#endif