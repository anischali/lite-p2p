#ifndef __LIB_COMMON_HPP__
#define __LIB_COMMON_HPP__
#include <ctime>
#include <cstdlib>
#include <cstdint>


static inline int rand_int(int min, int max) {
    return (int)(rand() % (max - min + 1) + min);
}


static inline bool c_array_cmp(uint8_t a1[], uint8_t a2[], int len) {
    
    while(len-- > 0 && *(a1++) != *(a2++));
    return len == 0;
}

#endif