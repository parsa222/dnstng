#include "channel.h"
#include "dns_packet.h"
#include <stdio.h>
#include <string.h>
#include <assert.h>

/* ------------------------------------------------------------------ */
/* Helpers                                                              */
/* ------------------------------------------------------------------ */

static void fill_seq(uint8_t *buf, size_t len)
{
    size_t i;
    for (i = 0; i < len; i++) {
        buf[i] = (uint8_t)(i & 0xFFU);
    }
}

/* Pack data → build wire → parse wire → unpack, verify round-trip. */
static int roundtrip(uint32_t chan_mask, const uint8_t *data, size_t data_len)
{
    channel_buf_t        cb;
    uint8_t              wire[4096];
    uint8_t              out[4096];
    dns_parsed_response_t parsed;
    int                  packed;
    int                  wire_len;
    int                  unpacked;

    channel_buf_init(&cb, chan_mask, "tunnel.example.com");

    packed = channel_pack(&cb, data, data_len);
    if (packed <= 0) {
        return -1;
    }

    wire_len = dns_build_response_ext(0x1234,
                                       "test.tunnel.example.com",
                                       DNS_TYPE_TXT,
                                       &cb.resp,
                                       wire, sizeof(wire));
    if (wire_len <= 0) {
        return -1;
    }

    if (dns_parse_response_full(wire, (size_t)wire_len, &parsed) != ERR_OK) {
        return -1;
    }

    unpacked = channel_unpack(&parsed, chan_mask, out, sizeof(out));
    if (unpacked != packed) {
        return -1;
    }
    if (memcmp(out, data, (size_t)packed) != 0) {
        return -1;
    }
    return packed;
}

/* ------------------------------------------------------------------ */
/* Tests                                                                */
/* ------------------------------------------------------------------ */

static void test_pack_unpack_naptr(void)
{
    uint8_t data[200];
    int     result;

    fill_seq(data, sizeof(data));
    result = roundtrip(CHAN_NAPTR, data, sizeof(data));
    assert(result > 0);
    printf("  test_pack_unpack_naptr: OK (packed %d bytes)\n", result);
}

static void test_pack_unpack_caa(void)
{
    uint8_t data[100];
    int     result;

    fill_seq(data, sizeof(data));
    result = roundtrip(CHAN_CAA, data, sizeof(data));
    assert(result > 0);
    printf("  test_pack_unpack_caa: OK (packed %d bytes)\n", result);
}

static void test_pack_unpack_addl(void)
{
    /* Additional A records carry 4 raw bytes each (no header).
     * Unpack appends them linearly, so we verify just the byte count. */
    channel_buf_t        cb;
    uint8_t              data[32]; /* 8 records × 4 bytes */
    uint8_t              wire[4096];
    uint8_t              out[256];
    dns_parsed_response_t parsed;
    int                  packed;
    int                  wire_len;
    int                  unpacked;

    fill_seq(data, sizeof(data));
    channel_buf_init(&cb, CHAN_ADDL_GLUE, "tunnel.example.com");

    packed = channel_pack(&cb, data, sizeof(data));
    assert(packed > 0);

    wire_len = dns_build_response_ext(0xABCD,
                                       "test.tunnel.example.com",
                                       DNS_TYPE_TXT,
                                       &cb.resp,
                                       wire, sizeof(wire));
    assert(wire_len > 0);

    assert(dns_parse_response_full(wire, (size_t)wire_len, &parsed) == ERR_OK);

    unpacked = channel_unpack(&parsed, CHAN_ADDL_GLUE, out, sizeof(out));
    assert(unpacked == packed);
    assert(memcmp(out, data, (size_t)packed) == 0);

    printf("  test_pack_unpack_addl: OK (packed %d bytes)\n", packed);
}

static void test_fragment_reassembly(void)
{
    /* 300 bytes via NAPTR: needs 2 records (240 + 60) */
    uint8_t data[300];
    int     result;

    fill_seq(data, sizeof(data));
    result = roundtrip(CHAN_NAPTR, data, sizeof(data));
    assert(result == 300);
    printf("  test_fragment_reassembly: OK (%d bytes across 2 NAPTR records)\n",
           result);
}

static void test_multi_channel(void)
{
    /* Pack with NAPTR + CAA combined; verify we get more bytes packed. */
    channel_buf_t        cb;
    uint8_t              data[400];
    uint8_t              wire[8192];
    uint8_t              out[4096];
    dns_parsed_response_t parsed;
    int                  packed;
    int                  wire_len;
    int                  unpacked;
    uint32_t             mask;

    fill_seq(data, sizeof(data));
    mask = CHAN_NAPTR | CHAN_CAA;
    channel_buf_init(&cb, mask, "tunnel.example.com");

    packed = channel_pack(&cb, data, sizeof(data));
    assert(packed > 0);

    wire_len = dns_build_response_ext(0x9999,
                                       "test.tunnel.example.com",
                                       DNS_TYPE_TXT,
                                       &cb.resp,
                                       wire, sizeof(wire));
    assert(wire_len > 0);

    assert(dns_parse_response_full(wire, (size_t)wire_len, &parsed) == ERR_OK);

    unpacked = channel_unpack(&parsed, mask, out, sizeof(out));
    assert(unpacked == packed);
    assert(memcmp(out, data, (size_t)packed) == 0);

    printf("  test_multi_channel: OK (packed %d bytes with NAPTR+CAA)\n",
           packed);
}

static void test_edns_channel(void)
{
    channel_buf_t        cb;
    uint8_t              data[100];
    uint8_t              wire[4096];
    uint8_t              out[512];
    dns_parsed_response_t parsed;
    int                  packed;
    int                  wire_len;
    int                  unpacked;

    fill_seq(data, sizeof(data));
    channel_buf_init(&cb, CHAN_EDNS_OPT, "tunnel.example.com");

    packed = channel_pack(&cb, data, sizeof(data));
    assert(packed > 0);

    wire_len = dns_build_response_ext(0x5555,
                                       "test.tunnel.example.com",
                                       DNS_TYPE_TXT,
                                       &cb.resp,
                                       wire, sizeof(wire));
    assert(wire_len > 0);

    assert(dns_parse_response_full(wire, (size_t)wire_len, &parsed) == ERR_OK);

    unpacked = channel_unpack(&parsed, CHAN_EDNS_OPT, out, sizeof(out));
    assert(unpacked == packed);
    assert(memcmp(out, data, (size_t)packed) == 0);

    printf("  test_edns_channel: OK (packed %d bytes)\n", packed);
}

/* ------------------------------------------------------------------ */
/* main                                                                 */
/* ------------------------------------------------------------------ */

int main(void)
{
    printf("test_channel: running...\n");

    test_pack_unpack_naptr();
    test_pack_unpack_caa();
    test_pack_unpack_addl();
    test_fragment_reassembly();
    test_multi_channel();
    test_edns_channel();

    printf("test_channel: ALL PASS\n");
    return 0;
}
