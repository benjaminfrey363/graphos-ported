#ifndef COMMON_H
#define COMMON_H


#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <iostream>
#include <string> 


#include "OMAP/Utilities.h"

/* OCall functions */
inline void ocall_print_string(const char *str) {
    /* Proxy/Bridge will check the length and null-terminate 
     * the input string to prevent buffer overflow. 
     */
    printf("%s", str);
}

inline void ocall_start_timer(int timerID) {
    Utilities::startTimer(timerID);
}

inline double ocall_stop_timer(int timerID) {
    return Utilities::stopTimer(timerID);
}
#endif // COMMON_H

