#pragma once
#include <stdint.h>
#include <stddef.h>

typedef enum { ENCODE_BASE36 = 0, ENCODE_BASE32 = 1 } encode_mode_t;

int encode_data(const uint8_t *in, size_t in_len,
                char *out, size_t out_cap, encode_mode_t mode);
int decode_data(const char *in, size_t in_len,
                uint8_t *out, size_t out_cap, encode_mode_t mode);
int encode_to_labels(const uint8_t *in, size_t in_len,
                     char *out, size_t out_cap, encode_mode_t mode);
int decode_from_labels(const char *in, size_t in_len,
                       uint8_t *out, size_t out_cap, encode_mode_t mode);
