#include "encode.h"
#include <stdio.h>
#include <string.h>
#include <assert.h>
#include <stdint.h>

static void test_base32_roundtrip(void)
{
    static const uint8_t input[]  = { 0x00, 0xFF, 0xAB, 0xCD, 0xEF, 0x01, 0x23 };
    char    encoded[64];
    uint8_t decoded[32];
    int     enc_len;
    int     dec_len;

    enc_len = encode_data(input, sizeof(input), encoded, sizeof(encoded),
                           ENCODE_BASE32);
    assert(enc_len > 0);
    printf("  base32 encoded: %s (len=%d)\n", encoded, enc_len);

    dec_len = decode_data(encoded, (size_t)enc_len, decoded, sizeof(decoded),
                           ENCODE_BASE32);
    assert(dec_len == (int)sizeof(input));
    assert(memcmp(input, decoded, sizeof(input)) == 0);
    printf("  base32 decode matches input\n");
}

static void test_base36_roundtrip(void)
{
    static const uint8_t input[]  = { 0xDE, 0xAD, 0xBE, 0xEF, 0x42 };
    char    encoded[64];
    uint8_t decoded[32];
    int     enc_len;
    int     dec_len;
    size_t  k;

    enc_len = encode_data(input, sizeof(input), encoded, sizeof(encoded),
                           ENCODE_BASE36);
    /* 5 bytes → exactly 8 base36 chars (20% more efficient than hex's 10) */
    assert(enc_len == 8);
    printf("  base36 encoded: %s (len=%d)\n", encoded, enc_len);

    /* Verify all chars are in [0-9a-z] */
    for (k = 0; k < (size_t)enc_len; k++) {
        char c = encoded[k];
        assert((c >= '0' && c <= '9') || (c >= 'a' && c <= 'z'));
    }

    dec_len = decode_data(encoded, (size_t)enc_len, decoded, sizeof(decoded),
                           ENCODE_BASE36);
    assert(dec_len == (int)sizeof(input));
    assert(memcmp(input, decoded, sizeof(input)) == 0);
    printf("  base36 decode matches input\n");
}

static void test_base36_partial_groups(void)
{
    /* Test encoding of 1, 2, 3, 4 bytes (partial groups) */
    static const int expected_chars[5] = { 0, 2, 4, 5, 7 };
    uint8_t  input[4] = { 0xAB, 0xCD, 0xEF, 0x01 };
    char     encoded[32];
    uint8_t  decoded[8];
    int      n;

    for (n = 1; n <= 4; n++) {
        int enc_len = encode_data(input, (size_t)n, encoded, sizeof(encoded),
                                   ENCODE_BASE36);
        assert(enc_len == expected_chars[n]);
        printf("  base36 %d byte(s) → %d chars: %.*s\n",
               n, enc_len, enc_len, encoded);

        int dec_len = decode_data(encoded, (size_t)enc_len, decoded,
                                   sizeof(decoded), ENCODE_BASE36);
        assert(dec_len == n);
        assert(memcmp(input, decoded, (size_t)n) == 0);
    }
    printf("  base36 partial groups: ok\n");
}

static void test_empty_input(void)
{
    char    encoded[16];
    uint8_t decoded[8];
    int     enc_len;
    int     dec_len;

    enc_len = encode_data(NULL, 0, encoded, sizeof(encoded), ENCODE_BASE32);
    assert(enc_len >= 0);

    enc_len = encode_data((const uint8_t *)"", 0, encoded, sizeof(encoded),
                           ENCODE_BASE32);
    assert(enc_len == 0);

    dec_len = decode_data("", 0, decoded, sizeof(decoded), ENCODE_BASE32);
    assert(dec_len == 0);
    printf("  empty input: ok\n");
}

static void test_single_byte(void)
{
    uint8_t input   = 0x61; /* 'a' */
    char    encoded[16];
    uint8_t decoded[4];
    int     enc_len;
    int     dec_len;

    enc_len = encode_data(&input, 1, encoded, sizeof(encoded), ENCODE_BASE32);
    assert(enc_len == 8);
    printf("  single byte base32: %s\n", encoded);

    dec_len = decode_data(encoded, (size_t)enc_len, decoded, sizeof(decoded),
                           ENCODE_BASE32);
    assert(dec_len == 1);
    assert(decoded[0] == 0x61);
}

static void test_labels_roundtrip(void)
{
    static const uint8_t input[] = "Hello, DNS tunnel!";
    char    labels[256];
    uint8_t decoded[64];
    int     llen;
    int     dec_len;
    size_t  input_len = sizeof(input) - 1; /* exclude NUL */

    llen = encode_to_labels(input, input_len, labels, sizeof(labels),
                              ENCODE_BASE32);
    assert(llen > 0);
    printf("  labels: %s (len=%d)\n", labels, llen);

    /* Verify dots are present for long enough data */
    dec_len = decode_from_labels(labels, (size_t)llen, decoded,
                                   sizeof(decoded), ENCODE_BASE32);
    assert(dec_len == (int)input_len);
    assert(memcmp(input, decoded, input_len) == 0);
    printf("  labels decode matches input\n");
}

static void test_labels_max_label_length(void)
{
    /* Create input that encodes to > 63 chars to verify dot splitting */
    uint8_t input[50];
    char    labels[256];
    uint8_t decoded[64];
    int     llen;
    int     dec_len;
    size_t  i;

    for (i = 0; i < sizeof(input); i++) {
        input[i] = (uint8_t)(i * 7 + 13);
    }

    llen = encode_to_labels(input, sizeof(input), labels, sizeof(labels),
                              ENCODE_BASE32);
    assert(llen > 0);

    /* Check that no label exceeds 63 chars */
    {
        const char *p   = labels;
        const char *dot;

        while ((dot = strchr(p, '.')) != NULL) {
            size_t label_len = (size_t)(dot - p);
            assert(label_len <= 63);
            p = dot + 1;
        }
        assert(strlen(p) <= 63);
    }
    printf("  label length constraint: ok\n");

    dec_len = decode_from_labels(labels, (size_t)llen, decoded,
                                   sizeof(decoded), ENCODE_BASE32);
    assert(dec_len == (int)sizeof(input));
    assert(memcmp(input, decoded, sizeof(input)) == 0);
}

int main(void)
{
    printf("test_encode: running...\n");

    printf("[1] base32 round-trip\n");
    test_base32_roundtrip();

    printf("[2] base36 round-trip\n");
    test_base36_roundtrip();

    printf("[2b] base36 partial groups\n");
    test_base36_partial_groups();

    printf("[3] empty input\n");
    test_empty_input();

    printf("[4] single byte\n");
    test_single_byte();

    printf("[5] labels round-trip\n");
    test_labels_roundtrip();

    printf("[6] labels max label length\n");
    test_labels_max_label_length();

    printf("test_encode: ALL PASS\n");
    return 0;
}
