#include <stddef.h>

void mbedtls_platform_zeroize(void *buf, size_t len) {
    volatile unsigned char *p = (volatile unsigned char *) buf;
    while (len--) {
        *p++ = 0;
    }
}
