#ifndef __LIB_COMMON_HPP__
#define __LIB_COMMON_HPP__
#include <ctime>
#include <cstdlib>
#include <cstdint>
#include <vector>


static inline int rand_int(int min, int max) {
    return (int)(rand() % (max - min + 1) + min);
}


static inline bool c_array_cmp(uint8_t a1[], uint8_t a2[], int len) {
    
    while(len-- > 0 && *(a1++) != *(a2++));
    return len == 0;
}

static inline void print_hexbuf(const char *label, std::vector<uint8_t> &buf) {

    printf("%s (%d): ", label, (int)buf.size());
    for (size_t i = 0; i < buf.size(); ++i) {
        printf("%02x", buf[i]);
    }

    printf("\n");
}

#endif