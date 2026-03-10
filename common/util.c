#include "util.h"
#include <string.h>

uint16_t crc16_ccitt(const uint8_t *data, size_t len)
{
    uint16_t crc = 0xFFFFU;
    size_t   i;

    for (i = 0; i < len; i++) {
        uint16_t x = (uint16_t)(((crc >> 8) ^ data[i]) & 0xFFU);
        x ^= x >> 4;
        crc = (uint16_t)((crc << 8)
                         ^ (uint16_t)(x << 12)
                         ^ (uint16_t)(x << 5)
                         ^ x);
    }
    return crc;
}

const char *err_str(err_t e)
{
    switch (e) {
    case ERR_OK:       return "OK";
    case ERR_NOMEM:    return "out of memory";
    case ERR_INVAL:    return "invalid argument";
    case ERR_OVERFLOW: return "buffer overflow";
    case ERR_IO:       return "I/O error";
    case ERR_TIMEOUT:  return "timeout";
    case ERR_NOTFOUND: return "not found";
    case ERR_PROTO:    return "protocol error";
    default:           return "unknown error";
    }
}

err_t safe_copy(void *dst, size_t dst_cap, const void *src, size_t len)
{
    if (!dst || !src) {
        return ERR_INVAL;
    }
    if (len > dst_cap) {
        return ERR_OVERFLOW;
    }
    memcpy(dst, src, len);
    return ERR_OK;
}
