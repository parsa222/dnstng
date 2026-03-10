#include "encode.h"
#include <string.h>
#include <stdint.h>

/* Base32 RFC 4648 lowercase alphabet */
static const char BASE32_ALPHA[33] = "abcdefghijklmnopqrstuvwxyz234567";

/* Base36 alphabet: [0-9a-z] — 36 chars, DNS-label safe, case-insensitive.
 * 5 bytes → 8 base36 chars (36^8 > 2^40).  20% more efficient than hex. */
static const char B36_ALPHA[37] = "0123456789abcdefghijklmnopqrstuvwxyz";

/* Number of base36 output chars required for k input bytes (k = 0..5). */
static const int B36_CHARS_FOR_BYTES[6] = { 0, 2, 4, 5, 7, 8 };

/* Bytes produced by a partial trailing group of r chars (r = in_len % 8).
 * -1 means that remainder length is invalid. */
static const int B36_BYTES_FOR_CHARS_REM[8] = { 0, -1, 1, -1, 2, 3, -1, 4 };

/* ------------------------------------------------------------------ */
/* Helpers                                                              */
/* ------------------------------------------------------------------ */

static int base32_char_value(char c)
{
    if (c >= 'a' && c <= 'z') {
        return c - 'a';
    }
    if (c >= 'A' && c <= 'Z') {
        return c - 'A';
    }
    if (c >= '2' && c <= '7') {
        return (c - '2') + 26;
    }
    return -1;
}

static int b36_char_value(char c)
{
    if (c >= '0' && c <= '9') {
        return c - '0';
    }
    if (c >= 'a' && c <= 'z') {
        return 10 + (c - 'a');
    }
    if (c >= 'A' && c <= 'Z') {
        return 10 + (c - 'A'); /* accept uppercase for robustness */
    }
    return -1;
}

/* ------------------------------------------------------------------ */
/* Base32 encode/decode                                                 */
/* ------------------------------------------------------------------ */

static int b32_encode(const uint8_t *in, size_t in_len,
                      char *out, size_t out_cap)
{
    size_t out_len = ((in_len + 4U) / 5U) * 8U;
    size_t i;
    size_t j = 0;

    if (in_len == 0) {
        if (out_cap < 1) {
            return -1;
        }
        out[0] = '\0';
        return 0;
    }

    if (out_cap <= out_len) {
        return -1;
    }

    for (i = 0; i < in_len; i += 5) {
        size_t  rem = in_len - i;
        uint8_t b0, b1, b2, b3, b4;

        if (rem > 5) {
            rem = 5;
        }

        b0 = in[i];
        b1 = (rem > 1) ? in[i + 1] : 0;
        b2 = (rem > 2) ? in[i + 2] : 0;
        b3 = (rem > 3) ? in[i + 3] : 0;
        b4 = (rem > 4) ? in[i + 4] : 0;

        out[j++] = BASE32_ALPHA[(b0 >> 3) & 0x1FU];
        out[j++] = BASE32_ALPHA[((b0 & 0x07U) << 2) | ((b1 >> 6) & 0x03U)];
        out[j++] = (rem > 1) ? BASE32_ALPHA[(b1 >> 1) & 0x1FU] : '=';
        out[j++] = (rem > 1)
                       ? BASE32_ALPHA[((b1 & 0x01U) << 4) | ((b2 >> 4) & 0x0FU)]
                       : '=';
        out[j++] = (rem > 2)
                       ? BASE32_ALPHA[((b2 & 0x0FU) << 1) | ((b3 >> 7) & 0x01U)]
                       : '=';
        out[j++] = (rem > 3) ? BASE32_ALPHA[(b3 >> 2) & 0x1FU] : '=';
        out[j++] = (rem > 3)
                       ? BASE32_ALPHA[((b3 & 0x03U) << 3) | ((b4 >> 5) & 0x07U)]
                       : '=';
        out[j++] = (rem > 4) ? BASE32_ALPHA[b4 & 0x1FU] : '=';
    }

    out[j] = '\0';
    return (int)j;
}

static int b32_decode(const char *in, size_t in_len,
                      uint8_t *out, size_t out_cap)
{
    size_t i;
    size_t j = 0;
    size_t num_groups;
    size_t trailing_pad;
    size_t exact_out;

    if (in_len == 0) {
        return 0;
    }

    if (in_len % 8 != 0) {
        return -1;
    }

    /* Count trailing '=' to determine exact output size */
    trailing_pad = 0;
    {
        size_t k = in_len;
        while (k > 0 && in[k - 1] == '=') {
            trailing_pad++;
            k--;
        }
    }

    num_groups = in_len / 8;
    /*
     * Each group of 8 chars encodes 5 bytes, minus bytes removed by padding:
     *   pad=0 → 5 bytes, pad=1 → 4 bytes, pad=3 → 3 bytes,
     *   pad=4 → 2 bytes, pad=6 → 1 byte
     */
    exact_out = num_groups * 5;
    if (trailing_pad == 1) { exact_out -= 1; }
    else if (trailing_pad == 3) { exact_out -= 2; }
    else if (trailing_pad == 4) { exact_out -= 3; }
    else if (trailing_pad == 6) { exact_out -= 4; }

    if (out_cap < exact_out) {
        return -1;
    }

    for (i = 0; i < in_len; i += 8) {
        int    c[8];
        int    k;
        int    pad = 0;

        for (k = 0; k < 8; k++) {
            if (in[i + (size_t)k] == '=') {
                c[k] = 0;
                pad++;
            } else {
                c[k] = base32_char_value(in[i + (size_t)k]);
                if (c[k] < 0) {
                    return -1;
                }
            }
        }

        out[j++] = (uint8_t)((c[0] << 3) | (c[1] >> 2));
        if (pad < 6) {
            out[j++] = (uint8_t)((c[1] << 6) | (c[2] << 1) | (c[3] >> 4));
        }
        if (pad < 4) {
            out[j++] = (uint8_t)((c[3] << 4) | (c[4] >> 1));
        }
        if (pad < 2) {
            out[j++] = (uint8_t)((c[4] << 7) | (c[5] << 2) | (c[6] >> 3));
        }
        if (pad == 0) {
            out[j++] = (uint8_t)((c[6] << 5) | c[7]);
        }
    }

    return (int)j;
}

/* ------------------------------------------------------------------ */
/* Base36 encode/decode                                                 */
/* ------------------------------------------------------------------ */

/* Write nchars base36 digits of val into out[0..nchars-1], big-endian. */
static void encode_b36_group(uint64_t val, int nchars, char *out)
{
    int i;
    for (i = nchars - 1; i >= 0; i--) {
        out[i] = B36_ALPHA[val % 36U];
        val    /= 36U;
    }
}

/* Read nchars base36 digits from in[0..nchars-1] into *val_out.
 * Returns 0 on success, -1 if a character is not a valid base36 digit. */
static int decode_b36_group(const char *in, int nchars, uint64_t *val_out)
{
    uint64_t val = 0;
    int      i;
    for (i = 0; i < nchars; i++) {
        int cv = b36_char_value(in[i]);
        if (cv < 0) {
            return -1;
        }
        val = val * 36U + (uint64_t)cv;
    }
    *val_out = val;
    return 0;
}

static int b36_encode(const uint8_t *in, size_t in_len,
                      char *out, size_t out_cap)
{
    size_t i = 0;
    size_t j = 0;

    if (in_len == 0) {
        if (out_cap < 1) {
            return -1;
        }
        out[0] = '\0';
        return 0;
    }

    while (i < in_len) {
        size_t   rem   = in_len - i;
        size_t   group = (rem > 5U) ? 5U : rem;
        size_t   k;
        uint64_t val   = 0;
        int      nchars;

        for (k = 0; k < group; k++) {
            val = (val << 8) | in[i + k];
        }

        nchars = B36_CHARS_FOR_BYTES[group];
        if (j + (size_t)nchars + 1U > out_cap) {
            return -1;
        }
        encode_b36_group(val, nchars, out + j);
        j += (size_t)nchars;
        i += group;
    }

    out[j] = '\0';
    return (int)j;
}

static int b36_decode(const char *in, size_t in_len,
                      uint8_t *out, size_t out_cap)
{
    int    rem_bytes;
    size_t full_groups;
    size_t last_bytes;
    size_t total_out;
    size_t g;
    size_t i;
    size_t j;

    if (in_len == 0) {
        return 0;
    }

    rem_bytes = B36_BYTES_FOR_CHARS_REM[in_len % 8U];
    if (rem_bytes < 0) {
        return -1; /* invalid encoded string length */
    }

    full_groups = in_len / 8U;
    last_bytes  = (size_t)rem_bytes;
    total_out   = full_groups * 5U + last_bytes;

    if (out_cap < total_out) {
        return -1;
    }

    i = 0;
    j = 0;

    for (g = 0; g < full_groups; g++) {
        uint64_t val = 0;
        int      k;

        if (decode_b36_group(in + i, 8, &val) < 0) {
            return -1;
        }
        /* Extract 5 bytes big-endian */
        for (k = 4; k >= 0; k--) {
            out[j + (size_t)k] = (uint8_t)(val & 0xFFU);
            val >>= 8;
        }
        i += 8U;
        j += 5U;
    }

    if (last_bytes > 0U) {
        int      nchars = B36_CHARS_FOR_BYTES[last_bytes];
        uint64_t val    = 0;
        int      k;

        if (decode_b36_group(in + i, nchars, &val) < 0) {
            return -1;
        }
        for (k = (int)last_bytes - 1; k >= 0; k--) {
            out[j + (size_t)k] = (uint8_t)(val & 0xFFU);
            val >>= 8;
        }
    }

    return (int)total_out;
}

/* ------------------------------------------------------------------ */
/* Public API                                                           */
/* ------------------------------------------------------------------ */

int encode_data(const uint8_t *in, size_t in_len,
                char *out, size_t out_cap, encode_mode_t mode)
{
    if (!out || out_cap == 0) {
        return -1;
    }
    /* Allow NULL pointer with zero length as empty-input shorthand */
    if (!in || in_len == 0) {
        out[0] = '\0';
        return 0;
    }

    if (mode == ENCODE_BASE32) {
        return b32_encode(in, in_len, out, out_cap);
    }
    return b36_encode(in, in_len, out, out_cap);
}

int decode_data(const char *in, size_t in_len,
                uint8_t *out, size_t out_cap, encode_mode_t mode)
{
    if (!in || !out || out_cap == 0) {
        return -1;
    }

    if (mode == ENCODE_BASE32) {
        return b32_decode(in, in_len, out, out_cap);
    }
    return b36_decode(in, in_len, out, out_cap);
}

/* Split encoded string into DNS labels of at most 63 chars each,
 * separated by '.'.  Writes NUL-terminated result into out.
 * Returns number of chars written (not counting NUL) or -1 on error. */
int encode_to_labels(const uint8_t *in, size_t in_len,
                     char *out, size_t out_cap, encode_mode_t mode)
{
    char    encoded[2048];
    int     enc_len;
    size_t  pos     = 0;
    size_t  out_pos = 0;
    size_t  label_len;

    if (!in || !out || out_cap == 0) {
        return -1;
    }

    enc_len = encode_data(in, in_len, encoded, sizeof(encoded), mode);
    if (enc_len < 0) {
        return -1;
    }

    while (pos < (size_t)enc_len) {
        label_len = (size_t)enc_len - pos;
        if (label_len > 63) {
            label_len = 63;
        }

        /* Need label_len chars + optional dot + NUL */
        if (out_pos + label_len + 2 > out_cap) {
            return -1;
        }

        if (out_pos > 0) {
            out[out_pos++] = '.';
        }

        memcpy(out + out_pos, encoded + pos, label_len);
        out_pos += label_len;
        pos     += label_len;
    }

    out[out_pos] = '\0';
    return (int)out_pos;
}

/* Strip dots and decode.
 * Returns number of decoded bytes or -1 on error. */
int decode_from_labels(const char *in, size_t in_len,
                       uint8_t *out, size_t out_cap, encode_mode_t mode)
{
    char   stripped[2048];
    size_t strip_len = 0;
    size_t i;

    if (!in || !out || out_cap == 0) {
        return -1;
    }

    /* Copy everything except '.' characters */
    for (i = 0; i < in_len; i++) {
        if (in[i] != '.') {
            if (strip_len >= sizeof(stripped) - 1) {
                return -1;
            }
            stripped[strip_len++] = in[i];
        }
    }
    stripped[strip_len] = '\0';

    return decode_data(stripped, strip_len, out, out_cap, mode);
}
