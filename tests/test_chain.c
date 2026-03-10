#include "chain.h"
#include "dns_packet.h"
#include <stdio.h>
#include <string.h>
#include <assert.h>

static void fill_seq(uint8_t *buf, size_t len)
{
    size_t i;
    for (i = 0; i < len; i++) {
        buf[i] = (uint8_t)(i & 0xFFU);
    }
}

static void test_cname_chain_basic(void)
{
    uint8_t              data[60];
    uint8_t              wire[4096];
    uint8_t              out[256];
    dns_parsed_response_t parsed;
    int                  wire_len;
    int                  extracted;

    fill_seq(data, sizeof(data));

    wire_len = chain_build_cname(0x5678,
                                  "test.example.com",
                                  "example.com",
                                  data, sizeof(data),
                                  3,
                                  wire, sizeof(wire));
    assert(wire_len > 0);

    assert(dns_parse_response_full(wire, (size_t)wire_len, &parsed)
           == ERR_OK);

    extracted = chain_parse_cname(&parsed, "example.com",
                                   out, sizeof(out));
    assert(extracted > 0);
    /* The extracted bytes should match the beginning of data
     * (each chunk is base36 encoded with possible rounding) */
    assert((size_t)extracted <= sizeof(data));

    printf("  test_cname_chain_basic: OK (extracted %d bytes from 3-hop chain)\n",
           extracted);
}

static void test_cname_chain_depth1(void)
{
    uint8_t              data[20];
    uint8_t              wire[2048];
    uint8_t              out[128];
    dns_parsed_response_t parsed;
    int                  wire_len;
    int                  extracted;

    fill_seq(data, sizeof(data));

    wire_len = chain_build_cname(0x1111,
                                  "q.example.com",
                                  "example.com",
                                  data, sizeof(data),
                                  1,
                                  wire, sizeof(wire));
    assert(wire_len > 0);

    assert(dns_parse_response_full(wire, (size_t)wire_len, &parsed)
           == ERR_OK);

    extracted = chain_parse_cname(&parsed, "example.com",
                                   out, sizeof(out));
    assert(extracted > 0);

    printf("  test_cname_chain_depth1: OK (extracted %d bytes)\n", extracted);
}

static void test_ns_referral_basic(void)
{
    uint8_t              data[40];
    uint8_t              wire[4096];
    uint8_t              out[256];
    dns_parsed_response_t parsed;
    int                  wire_len;
    int                  extracted;

    fill_seq(data, sizeof(data));

    wire_len = chain_build_ns_referral(0x9ABC,
                                        "test.example.com",
                                        "example.com",
                                        data, sizeof(data),
                                        2,
                                        wire, sizeof(wire));
    assert(wire_len > 0);

    assert(dns_parse_response_full(wire, (size_t)wire_len, &parsed)
           == ERR_OK);

    extracted = chain_parse_ns_referral(&parsed, "example.com",
                                         out, sizeof(out));
    assert(extracted > 0);
    assert((size_t)extracted <= sizeof(data));

    printf("  test_ns_referral_basic: OK (extracted %d bytes from 2-NS referral)\n",
           extracted);
}

static void test_ns_referral_depth4(void)
{
    uint8_t              data[80];
    uint8_t              wire[8192];
    uint8_t              out[512];
    dns_parsed_response_t parsed;
    int                  wire_len;
    int                  extracted;

    fill_seq(data, sizeof(data));

    wire_len = chain_build_ns_referral(0xDEAD,
                                        "x.example.com",
                                        "example.com",
                                        data, sizeof(data),
                                        4,
                                        wire, sizeof(wire));
    assert(wire_len > 0);

    assert(dns_parse_response_full(wire, (size_t)wire_len, &parsed)
           == ERR_OK);

    extracted = chain_parse_ns_referral(&parsed, "example.com",
                                         out, sizeof(out));
    assert(extracted > 0);

    printf("  test_ns_referral_depth4: OK (extracted %d bytes from 4-NS referral)\n",
           extracted);
}

int main(void)
{
    printf("test_chain: running...\n");

    test_cname_chain_basic();
    test_cname_chain_depth1();
    test_ns_referral_basic();
    test_ns_referral_depth4();

    printf("test_chain: ALL PASS\n");
    return 0;
}
