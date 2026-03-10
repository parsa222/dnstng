#pragma once
#include <stddef.h>
#include "util.h"

err_t compress_data(const uint8_t *in, size_t in_len,
                    uint8_t *out, size_t out_cap, size_t *out_len);
err_t decompress_data(const uint8_t *in, size_t in_len,
                      uint8_t *out, size_t out_cap, size_t *out_len);
