#include <stdio.h>
#ifndef NONCE
#define NONCE "fixture"
#endif
__attribute__((constructor)) static void report(void) { puts("LIB-RAN " NONCE); }
