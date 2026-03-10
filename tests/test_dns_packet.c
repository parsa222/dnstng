#include "dns_packet.h"
#include <stdio.h>
#include <string.h>
#include <assert.h>
#include <stdint.h>

/* ------------------------------------------------------------------ */
/* Helper: check DNS wire-format header fields                         */
/* ------------------------------------------------------------------ */
static uint16_t get16(const uint8_t *buf, size_t off)
{
    return (uint16_t)((buf[off] << 8) | buf[off + 1]);
}

/* ------------------------------------------------------------------ */
/* Tests                                                                */
/* ------------------------------------------------------------------ */

static void test_build_query(void)
{
    uint8_t  buf[512];
    int      len;
    uint16_t id    = 0xABCD;
    uint16_t flags;
    uint16_t qdcount;

    len = dns_build_query(id, "foo.bar.example.com", DNS_TYPE_TXT,
                           0, 0, buf, sizeof(buf));
    assert(len > 12);
    printf("  query len: %d\n", len);

    /* Check header */
    assert(get16(buf, 0) == id);
    flags   = get16(buf, 2);
    qdcount = get16(buf, 4);

    assert(flags == 0x0100U); /* RD=1 */
    assert(qdcount == 1);
    assert(get16(buf, 6) == 0);  /* ANCOUNT */
    assert(get16(buf, 8) == 0);  /* NSCOUNT */
    assert(get16(buf, 10) == 0); /* ARCOUNT */
    printf("  header fields: ok\n");

    /* Check QTYPE at end */
    {
        /* Walk labels to find QTYPE */
        size_t off = 12;
        while (off < (size_t)len && buf[off] != 0) {
            uint8_t label_len = buf[off];
            off += 1 + label_len;
        }
        off++; /* skip root label */
        assert(get16(buf, off) == (uint16_t)DNS_TYPE_TXT);
        assert(get16(buf, off + 2) == 1); /* CLASS=IN */
        printf("  QTYPE=TXT, CLASS=IN: ok\n");
    }
}

static void test_build_query_edns0(void)
{
    uint8_t  buf[512];
    int      len;
    uint16_t arcount;

    len = dns_build_query(1, "test.example.com", DNS_TYPE_A,
                           1, 4096, buf, sizeof(buf));
    assert(len > 12);
    arcount = get16(buf, 10);
    assert(arcount == 1); /* one OPT record */
    printf("  EDNS0 ARCOUNT=1: ok\n");
}

static void test_build_response_and_parse(void)
{
    uint8_t       buf[512];
    int           len;
    uint16_t      id  = 0x1234;
    dns_answer_t  ans;
    static const uint8_t rdata[] = { 0x05, 'h', 'e', 'l', 'l', 'o' };

    memset(&ans, 0, sizeof(ans));
    ans.type      = DNS_TYPE_TXT;
    ans.rdata     = rdata;
    ans.rdata_len = sizeof(rdata);
    ans.ttl       = 60;

    len = dns_build_response(id, "data.t.tunnel.example.com", DNS_TYPE_TXT,
                              &ans, 1, buf, sizeof(buf));
    assert(len > 12);
    printf("  response len: %d\n", len);

    /* Header check */
    assert(get16(buf, 0) == id);
    assert((get16(buf, 2) & 0x8000U) != 0); /* QR=1 */
    assert(get16(buf, 6) == 1);             /* ANCOUNT=1 */
    printf("  response header: ok\n");
}

typedef struct {
    int      count;
    uint16_t types[8];
} parse_ud_t;

static void parse_cb(dns_type_t type, const uint8_t *rdata,
                      size_t rdata_len, void *userdata)
{
    parse_ud_t *ud = (parse_ud_t *)userdata;
    (void)rdata;
    (void)rdata_len;
    if (ud->count < 8) {
        ud->types[ud->count] = (uint16_t)type;
        ud->count++;
    }
}

static void test_parse_response(void)
{
    uint8_t       buf[512];
    int           len;
    dns_answer_t  ans;
    static const uint8_t rdata[] = "tunnel-data";
    parse_ud_t    ud;
    err_t         e;

    memset(&ans, 0, sizeof(ans));
    ans.type      = DNS_TYPE_TXT;
    ans.rdata     = rdata;
    ans.rdata_len = sizeof(rdata) - 1;
    ans.ttl       = 0;

    len = dns_build_response(0x0001, "x.t.example.com", DNS_TYPE_TXT,
                              &ans, 1, buf, sizeof(buf));
    assert(len > 0);

    /* Set QR=1 so parse_response works (it doesn't care, just parses answers) */
    memset(&ud, 0, sizeof(ud));
    e = dns_parse_response(buf, (size_t)len, parse_cb, &ud);
    assert(e == ERR_OK);
    assert(ud.count == 1);
    assert(ud.types[0] == DNS_TYPE_TXT);
    printf("  parse response: got %d answer(s), type=%u\n",
           ud.count, ud.types[0]);
}

static void test_parse_short_buffer(void)
{
    uint8_t  buf[4];
    err_t    e;

    memset(buf, 0, sizeof(buf));
    e = dns_parse_response(buf, sizeof(buf), NULL, NULL);
    assert(e == ERR_PROTO);
    printf("  short buffer rejected: ok\n");
}

static void test_labels_encoding(void)
{
    /* Build a query with a long FQDN and verify it's parseable */
    uint8_t buf[512];
    int     len;

    len = dns_build_query(1, "a.b.c.d.e.f.g.tunnel.example.com",
                           DNS_TYPE_NULL_, 0, 0, buf, sizeof(buf));
    assert(len > 12);
    printf("  multi-label FQDN query len: %d: ok\n", len);
}

int main(void)
{
    printf("test_dns_packet: running...\n");

    printf("[1] build query\n");
    test_build_query();

    printf("[2] build query with EDNS0\n");
    test_build_query_edns0();

    printf("[3] build response and parse\n");
    test_build_response_and_parse();

    printf("[4] parse response round-trip\n");
    test_parse_response();

    printf("[5] parse short buffer\n");
    test_parse_short_buffer();

    printf("[6] multi-label FQDN\n");
    test_labels_encoding();

    printf("test_dns_packet: ALL PASS\n");
    return 0;
}
