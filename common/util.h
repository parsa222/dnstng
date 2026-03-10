#pragma once
#include <stdint.h>
#include <stddef.h>

typedef enum {
    ERR_OK       =  0,
    ERR_NOMEM    = -1,
    ERR_INVAL    = -2,
    ERR_OVERFLOW = -3,
    ERR_IO       = -4,
    ERR_TIMEOUT  = -5,
    ERR_NOTFOUND = -6,
    ERR_PROTO    = -7,
} err_t;

uint16_t    crc16_ccitt(const uint8_t *data, size_t len);
const char *err_str(err_t e);
err_t       safe_copy(void *dst, size_t dst_cap, const void *src, size_t len);
