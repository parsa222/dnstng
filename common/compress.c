#include "compress.h"
#include <lz4.h>
#include <string.h>

err_t compress_data(const uint8_t *in, size_t in_len,
                    uint8_t *out, size_t out_cap, size_t *out_len)
{
    int result;

    if (!in || !out || !out_len || in_len == 0) {
        return ERR_INVAL;
    }
    if (in_len > (size_t)LZ4_MAX_INPUT_SIZE) {
        return ERR_OVERFLOW;
    }

    result = LZ4_compress_default((const char *)in, (char *)out,
                                   (int)in_len, (int)out_cap);
    if (result <= 0) {
        return ERR_OVERFLOW;
    }

    *out_len = (size_t)result;
    return ERR_OK;
}

err_t decompress_data(const uint8_t *in, size_t in_len,
                      uint8_t *out, size_t out_cap, size_t *out_len)
{
    int result;

    if (!in || !out || !out_len || in_len == 0) {
        return ERR_INVAL;
    }

    result = LZ4_decompress_safe((const char *)in, (char *)out,
                                  (int)in_len, (int)out_cap);
    if (result < 0) {
        return ERR_PROTO;
    }

    *out_len = (size_t)result;
    return ERR_OK;
}
