/*
 * test_integration.c — End-to-end integration test for the tunnel data path.
 *
 * This test exercises the FULL pipeline that a real DNS query/response
 * traverses, without actual UDP sockets.  It simulates:
 *
 *  1. Client builds a SYN with channel bitmask → server parses it, creates
 *     session, negotiates channels, builds SYN-ACK → client parses SYN-ACK.
 *  2. Client builds DATA packets → encodes to FQDN → server decodes FQDN →
 *     extracts transport packet → builds multi-channel response → wire →
 *     client parses wire → channel_unpack → transport_parse → verifies data.
 *  3. CNAME chain build → parse round-trip with embedded transport data.
 *  4. NS referral chain build → parse round-trip.
 *  5. Multi-channel (NAPTR+CAA+AUTH_NS+EDNS) full pipeline.
 */

#include "transport.h"
#include "channel.h"
#include "chain.h"
#include "dns_packet.h"
#include "encode.h"
#include "config.h"
#include "log.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <assert.h>

#define DOMAIN "example.com"

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

/* Parse tunnel FQDN the same way the server does:
 *   {encoded_data_labels}.{session_4hex}.t.{domain}
 * Returns 0 on success, -1 on failure. */
static int parse_tunnel_fqdn(const char *fqdn, const char *domain,
                               uint16_t *session_id_out,
                               char *encoded_out, size_t encoded_cap)
{
    size_t fqdn_len = strlen(fqdn);
    char   suffix[320];
    size_t suffix_len;
    const char *suffix_start;
    const char *dot;
    const char *session_start;
    const char *encoded_end;
    size_t      session_len;
    char        session_hex[8];
    unsigned long sid;

    snprintf(suffix, sizeof(suffix), ".t.%s", domain);
    suffix_len = strlen(suffix);

    if (fqdn_len <= suffix_len) { return -1; }
    if (strncasecmp(fqdn + fqdn_len - suffix_len, suffix, suffix_len) != 0) {
        return -1;
    }

    suffix_start = fqdn + fqdn_len - suffix_len;

    /* Find dot before session label */
    dot = NULL;
    {
        const char *scan = suffix_start - 1;
        while (scan >= fqdn) {
            if (*scan == '.') { dot = scan; break; }
            scan--;
        }
    }

    if (dot) {
        session_start = dot + 1;
        session_len   = (size_t)(suffix_start - session_start);
        encoded_end   = dot;
    } else {
        session_start = fqdn;
        session_len   = (size_t)(suffix_start - fqdn);
        encoded_end   = fqdn;
    }

    if (session_len != 4) { return -1; }

    memcpy(session_hex, session_start, 4);
    session_hex[4] = '\0';
    sid = strtoul(session_hex, NULL, 16);
    *session_id_out = (uint16_t)sid;

    {
        size_t enc_len = (size_t)(encoded_end - fqdn);
        if (enc_len >= encoded_cap) { return -1; }
        if (enc_len > 0) { memcpy(encoded_out, fqdn, enc_len); }
        encoded_out[enc_len] = '\0';
    }
    return 0;
}

/* ------------------------------------------------------------------ */
/* Test 1: SYN handshake with channel negotiation                       */
/* ------------------------------------------------------------------ */

static void test_syn_handshake(void)
{
    transport_ctx_t client_ctx;
    transport_ctx_t server_ctx;
    uint16_t        session_id = 0x0042;
    uint32_t        client_chans = CHAN_NAPTR | CHAN_CAA | CHAN_AUTH_NS | CHAN_EDNS_OPT;
    uint32_t        server_chans = CHAN_NAPTR | CHAN_SOA_DATA | CHAN_AUTH_NS;
    uint32_t        expected_neg = client_chans & server_chans; /* NAPTR | AUTH_NS */
    uint8_t         pkt[TUNNEL_HEADER_SIZE + TUNNEL_MAX_PAYLOAD];
    int             pkt_len;
    tunnel_header_t hdr;
    const uint8_t  *payload;
    size_t          payload_len;
    err_t           e;
    uint32_t        negotiated;

    /* 1a. Client builds SYN with channel bitmask */
    transport_init(&client_ctx);
    {
        uint8_t syn_payload[4];
        syn_payload[0] = (uint8_t)(client_chans >> 24);
        syn_payload[1] = (uint8_t)((client_chans >> 16) & 0xFFU);
        syn_payload[2] = (uint8_t)((client_chans >>  8) & 0xFFU);
        syn_payload[3] = (uint8_t)(client_chans & 0xFFU);

        pkt_len = transport_build_packet(&client_ctx, session_id,
                                          TUNNEL_FLAG_SYN,
                                          syn_payload, 4, pkt, sizeof(pkt));
        assert(pkt_len > 0);
    }

    /* 1b. Server parses SYN */
    e = transport_parse_packet(pkt, (size_t)pkt_len, &hdr, &payload, &payload_len);
    assert(e == ERR_OK);
    assert(hdr.flags & TUNNEL_FLAG_SYN);
    assert(payload_len >= 4);

    {
        uint32_t cli_chans = ((uint32_t)payload[0] << 24) |
                             ((uint32_t)payload[1] << 16) |
                             ((uint32_t)payload[2] <<  8) |
                              (uint32_t)payload[3];
        assert(cli_chans == client_chans);
        negotiated = cli_chans & server_chans;
        assert(negotiated == expected_neg);
    }

    /* 1c. Server builds SYN-ACK with negotiated channels */
    transport_init(&server_ctx);
    server_ctx.active_channels = negotiated;
    {
        uint8_t syn_ack_payload[4];
        syn_ack_payload[0] = (uint8_t)(negotiated >> 24);
        syn_ack_payload[1] = (uint8_t)((negotiated >> 16) & 0xFFU);
        syn_ack_payload[2] = (uint8_t)((negotiated >>  8) & 0xFFU);
        syn_ack_payload[3] = (uint8_t)(negotiated & 0xFFU);

        pkt_len = transport_build_packet(&server_ctx, session_id,
                                          TUNNEL_FLAG_SYN | TUNNEL_FLAG_ACK,
                                          syn_ack_payload, 4,
                                          pkt, sizeof(pkt));
        assert(pkt_len > 0);
    }

    /* 1d. Client parses SYN-ACK and extracts negotiated channels */
    e = transport_parse_packet(pkt, (size_t)pkt_len, &hdr, &payload, &payload_len);
    assert(e == ERR_OK);
    assert((hdr.flags & (TUNNEL_FLAG_SYN | TUNNEL_FLAG_ACK)) ==
           (TUNNEL_FLAG_SYN | TUNNEL_FLAG_ACK));
    assert(payload_len >= 4);

    {
        uint32_t neg = ((uint32_t)payload[0] << 24) |
                       ((uint32_t)payload[1] << 16) |
                       ((uint32_t)payload[2] <<  8) |
                        (uint32_t)payload[3];
        assert(neg == expected_neg);
        client_ctx.active_channels = neg;
    }

    assert(client_ctx.active_channels == expected_neg);
    assert(server_ctx.active_channels == expected_neg);

    transport_free(&client_ctx);
    transport_free(&server_ctx);

    printf("  test_syn_handshake: OK (negotiated=0x%08x)\n",
           (unsigned)expected_neg);
}

/* ------------------------------------------------------------------ */
/* Test 2: Full data round-trip — transport + multi-channel + wire      */
/* ------------------------------------------------------------------ */

static void test_data_roundtrip_multichannel(void)
{
    transport_ctx_t  client_ctx;
    transport_ctx_t  server_ctx;
    uint16_t         session_id = 0x0099;
    uint32_t         channels   = CHAN_NAPTR | CHAN_CAA;
    uint8_t          test_data[100];
    uint8_t          pkt[512];
    int              pkt_len;
    channel_buf_t    cb;
    uint8_t          wire[4096];
    int              wire_len;
    dns_parsed_response_t parsed;
    uint8_t          flat[4096];
    int              flat_len;
    tunnel_header_t  hdr;
    const uint8_t   *payload;
    size_t           payload_len;
    err_t            e;

    fill_seq(test_data, sizeof(test_data));

    /* Client: build a DATA packet */
    transport_init(&client_ctx);
    client_ctx.active_channels = channels;
    pkt_len = transport_build_packet(&client_ctx, session_id,
                                      TUNNEL_FLAG_DATA | TUNNEL_FLAG_ACK,
                                      test_data, sizeof(test_data),
                                      pkt, sizeof(pkt));
    assert(pkt_len > 0);

    /* Server: receive the packet (simulated), build multi-channel response */
    transport_init(&server_ctx);
    server_ctx.active_channels = channels;

    /* Server would parse the incoming client data here, then build response.
     * For this test we simulate the server building a response with the same
     * transport packet data (echoing back). */
    {
        uint8_t server_pkt[512];
        int     server_pkt_len;

        server_pkt_len = transport_build_packet(&server_ctx, session_id,
                                                 TUNNEL_FLAG_DATA | TUNNEL_FLAG_ACK,
                                                 test_data, sizeof(test_data),
                                                 server_pkt, sizeof(server_pkt));
        assert(server_pkt_len > 0);

        /* Pack into multi-channel DNS response */
        channel_buf_init(&cb, channels, DOMAIN);
        {
            int packed = channel_pack(&cb, server_pkt, (size_t)server_pkt_len);
            assert(packed > 0);
        }

        /* Build DNS wire-format response */
        wire_len = dns_build_response_ext(0x1234,
                                           "x.t." DOMAIN,
                                           DNS_TYPE_TXT,
                                           &cb.resp,
                                           wire, sizeof(wire));
        assert(wire_len > 0);
    }

    /* Client: parse the DNS wire response */
    e = dns_parse_response_full(wire, (size_t)wire_len, &parsed);
    assert(e == ERR_OK);

    /* Client: unpack multi-channel data */
    flat_len = channel_unpack(&parsed, channels, flat, sizeof(flat));
    assert(flat_len > 0);

    /* Client: parse transport packet from flat data */
    e = transport_parse_packet(flat, (size_t)flat_len, &hdr, &payload, &payload_len);
    assert(e == ERR_OK);
    assert(hdr.flags & TUNNEL_FLAG_DATA);
    assert(payload_len == sizeof(test_data));
    assert(memcmp(payload, test_data, sizeof(test_data)) == 0);

    transport_free(&client_ctx);
    transport_free(&server_ctx);

    printf("  test_data_roundtrip_multichannel: OK (%zu bytes through NAPTR+CAA)\n",
           sizeof(test_data));
}

/* ------------------------------------------------------------------ */
/* Test 3: Full round-trip with CNAME chain                             */
/* ------------------------------------------------------------------ */

static void test_data_roundtrip_cname_chain(void)
{
    transport_ctx_t  server_ctx;
    uint16_t         session_id = 0x00AA;
    uint8_t          test_data[50];
    uint8_t          pkt[512];
    int              pkt_len;
    uint8_t          wire[4096];
    int              wire_len;
    dns_parsed_response_t parsed;
    uint8_t          chain_data[4096];
    int              chain_len;
    tunnel_header_t  hdr;
    const uint8_t   *payload;
    size_t           payload_len;
    err_t            e;

    fill_seq(test_data, sizeof(test_data));

    /* Server: build transport packet */
    transport_init(&server_ctx);
    pkt_len = transport_build_packet(&server_ctx, session_id,
                                      TUNNEL_FLAG_DATA | TUNNEL_FLAG_ACK,
                                      test_data, sizeof(test_data),
                                      pkt, sizeof(pkt));
    assert(pkt_len > 0);

    /* Server: build CNAME chain response */
    wire_len = chain_build_cname(0x2222,
                                  "x.t." DOMAIN,
                                  DOMAIN,
                                  pkt, (size_t)pkt_len,
                                  3,
                                  wire, sizeof(wire));
    assert(wire_len > 0);

    /* Client: parse the CNAME chain */
    e = dns_parse_response_full(wire, (size_t)wire_len, &parsed);
    assert(e == ERR_OK);

    chain_len = chain_parse_cname(&parsed, DOMAIN, chain_data, sizeof(chain_data));
    assert(chain_len > 0);

    /* Client: parse transport from chain data */
    e = transport_parse_packet(chain_data, (size_t)chain_len,
                                &hdr, &payload, &payload_len);
    assert(e == ERR_OK);
    assert(hdr.flags & TUNNEL_FLAG_DATA);
    assert(payload_len == sizeof(test_data));
    assert(memcmp(payload, test_data, sizeof(test_data)) == 0);

    transport_free(&server_ctx);

    printf("  test_data_roundtrip_cname_chain: OK (%zu bytes through 3-hop CNAME chain)\n",
           sizeof(test_data));
}

/* ------------------------------------------------------------------ */
/* Test 4: Full round-trip with NS referral chain                       */
/* ------------------------------------------------------------------ */

static void test_data_roundtrip_ns_chain(void)
{
    transport_ctx_t  server_ctx;
    uint16_t         session_id = 0x00BB;
    uint8_t          test_data[40];
    uint8_t          pkt[512];
    int              pkt_len;
    uint8_t          wire[4096];
    int              wire_len;
    dns_parsed_response_t parsed;
    uint8_t          chain_data[4096];
    int              chain_len;
    tunnel_header_t  hdr;
    const uint8_t   *payload;
    size_t           payload_len;
    err_t            e;

    fill_seq(test_data, sizeof(test_data));

    /* Server: build transport packet */
    transport_init(&server_ctx);
    pkt_len = transport_build_packet(&server_ctx, session_id,
                                      TUNNEL_FLAG_DATA | TUNNEL_FLAG_ACK,
                                      test_data, sizeof(test_data),
                                      pkt, sizeof(pkt));
    assert(pkt_len > 0);

    /* Server: build NS referral chain */
    wire_len = chain_build_ns_referral(0x3333,
                                        "x.t." DOMAIN,
                                        DOMAIN,
                                        pkt, (size_t)pkt_len,
                                        2,
                                        wire, sizeof(wire));
    assert(wire_len > 0);

    /* Client: parse NS chain */
    e = dns_parse_response_full(wire, (size_t)wire_len, &parsed);
    assert(e == ERR_OK);

    chain_len = chain_parse_ns_referral(&parsed, DOMAIN,
                                          chain_data, sizeof(chain_data));
    assert(chain_len > 0);

    /* Client: parse transport */
    e = transport_parse_packet(chain_data, (size_t)chain_len,
                                &hdr, &payload, &payload_len);
    assert(e == ERR_OK);
    assert(hdr.flags & TUNNEL_FLAG_DATA);
    assert(payload_len == sizeof(test_data));
    assert(memcmp(payload, test_data, sizeof(test_data)) == 0);

    transport_free(&server_ctx);

    printf("  test_data_roundtrip_ns_chain: OK (%zu bytes through 2-NS referral)\n",
           sizeof(test_data));
}

/* ------------------------------------------------------------------ */
/* Test 5: Full upstream + downstream pipeline (FQDN encode/decode)     */
/* ------------------------------------------------------------------ */

static void test_upstream_downstream_pipeline(void)
{
    transport_ctx_t  client_ctx;
    transport_ctx_t  server_ctx;
    uint16_t         session_id = 0x00CC;
    uint32_t         channels   = CHAN_NAPTR;
    uint8_t          test_data[] = "Hello, tunnel!";
    size_t           test_data_len = sizeof(test_data) - 1;

    /* ----- UPSTREAM: client → server ----- */

    /* Client: build transport DATA packet */
    uint8_t up_pkt[512];
    int     up_pkt_len;
    transport_init(&client_ctx);
    client_ctx.active_channels = channels;

    up_pkt_len = transport_build_packet(&client_ctx, session_id,
                                         TUNNEL_FLAG_DATA,
                                         test_data, test_data_len,
                                         up_pkt, sizeof(up_pkt));
    assert(up_pkt_len > 0);

    /* Client: encode into FQDN */
    char labels[512];
    int  llen = encode_to_labels(up_pkt, (size_t)up_pkt_len,
                                  labels, sizeof(labels), ENCODE_BASE32);
    assert(llen > 0);

    char fqdn[768];
    int  fqdn_len = snprintf(fqdn, sizeof(fqdn), "%s.%04x.t.%s",
                              labels, session_id, DOMAIN);
    assert(fqdn_len > 0 && (size_t)fqdn_len < sizeof(fqdn));

    /* Server: parse the FQDN */
    {
        uint16_t parsed_sid;
        char     encoded[512];
        int      r = parse_tunnel_fqdn(fqdn, DOMAIN, &parsed_sid,
                                         encoded, sizeof(encoded));
        assert(r == 0);
        assert(parsed_sid == session_id);

        /* Server: decode the labels */
        uint8_t  decoded[512];
        int      dec_len = decode_from_labels(encoded, strlen(encoded),
                                               decoded, sizeof(decoded),
                                               ENCODE_BASE32);
        assert(dec_len > 0);

        /* Server: parse transport packet */
        tunnel_header_t  hdr;
        const uint8_t   *payload;
        size_t           payload_len;
        err_t            e;

        e = transport_parse_packet(decoded, (size_t)dec_len,
                                    &hdr, &payload, &payload_len);
        assert(e == ERR_OK);
        assert(hdr.flags & TUNNEL_FLAG_DATA);
        assert(payload_len == test_data_len);
        assert(memcmp(payload, test_data, test_data_len) == 0);
    }

    /* ----- DOWNSTREAM: server → client ----- */

    /* Server: build response transport packet with echo data */
    uint8_t dn_pkt[512];
    int     dn_pkt_len;
    transport_init(&server_ctx);
    server_ctx.active_channels = channels;

    dn_pkt_len = transport_build_packet(&server_ctx, session_id,
                                         TUNNEL_FLAG_DATA | TUNNEL_FLAG_ACK,
                                         test_data, test_data_len,
                                         dn_pkt, sizeof(dn_pkt));
    assert(dn_pkt_len > 0);

    /* Server: multi-channel pack */
    channel_buf_t cb;
    channel_buf_init(&cb, channels, DOMAIN);
    {
        int packed = channel_pack(&cb, dn_pkt, (size_t)dn_pkt_len);
        assert(packed > 0);
    }

    /* Server: build DNS wire response */
    uint8_t wire[4096];
    int     wire_len;
    wire_len = dns_build_response_ext(0x5678, fqdn, DNS_TYPE_TXT,
                                       &cb.resp, wire, sizeof(wire));
    assert(wire_len > 0);

    /* Client: parse DNS wire response */
    dns_parsed_response_t parsed;
    err_t e = dns_parse_response_full(wire, (size_t)wire_len, &parsed);
    assert(e == ERR_OK);

    /* Client: channel unpack */
    uint8_t flat[4096];
    int     flat_len = channel_unpack(&parsed, channels, flat, sizeof(flat));
    assert(flat_len > 0);

    /* Client: parse transport */
    {
        tunnel_header_t  hdr;
        const uint8_t   *payload;
        size_t           payload_len;

        e = transport_parse_packet(flat, (size_t)flat_len,
                                    &hdr, &payload, &payload_len);
        assert(e == ERR_OK);
        assert(hdr.flags & TUNNEL_FLAG_DATA);
        assert(payload_len == test_data_len);
        assert(memcmp(payload, test_data, test_data_len) == 0);
    }

    transport_free(&client_ctx);
    transport_free(&server_ctx);

    printf("  test_upstream_downstream_pipeline: OK (%zu bytes both directions)\n",
           test_data_len);
}

/* ------------------------------------------------------------------ */
/* Test 6: All channels combined                                        */
/* ------------------------------------------------------------------ */

static void test_all_channels_combined(void)
{
    transport_ctx_t  server_ctx;
    uint16_t         session_id = 0x00DD;
    uint32_t         channels   = CHAN_NAPTR | CHAN_CAA | CHAN_SOA_DATA |
                                  CHAN_SRV | CHAN_AUTH_NS | CHAN_ADDL_GLUE |
                                  CHAN_EDNS_OPT;
    uint8_t          test_data[150];
    uint8_t          pkt[512];
    int              pkt_len;
    channel_buf_t    cb;
    uint8_t          wire[8192];
    int              wire_len;
    dns_parsed_response_t parsed;
    uint8_t          flat[8192];
    int              flat_len;
    tunnel_header_t  hdr;
    const uint8_t   *payload;
    size_t           payload_len;
    err_t            e;

    fill_seq(test_data, sizeof(test_data));

    /* Server: build transport packet */
    transport_init(&server_ctx);
    server_ctx.active_channels = channels;

    pkt_len = transport_build_packet(&server_ctx, session_id,
                                      TUNNEL_FLAG_DATA | TUNNEL_FLAG_ACK,
                                      test_data, sizeof(test_data),
                                      pkt, sizeof(pkt));
    assert(pkt_len > 0);

    /* Pack into all channels */
    channel_buf_init(&cb, channels, DOMAIN);
    {
        int packed = channel_pack(&cb, pkt, (size_t)pkt_len);
        assert(packed > 0);
    }

    /* Build DNS wire response */
    wire_len = dns_build_response_ext(0xABCD,
                                       "x.t." DOMAIN,
                                       DNS_TYPE_TXT,
                                       &cb.resp,
                                       wire, sizeof(wire));
    assert(wire_len > 0);

    /* Parse response */
    e = dns_parse_response_full(wire, (size_t)wire_len, &parsed);
    assert(e == ERR_OK);

    /* Unpack */
    flat_len = channel_unpack(&parsed, channels, flat, sizeof(flat));
    assert(flat_len > 0);

    /* Parse transport */
    e = transport_parse_packet(flat, (size_t)flat_len, &hdr, &payload, &payload_len);
    assert(e == ERR_OK);
    assert(hdr.flags & TUNNEL_FLAG_DATA);
    assert(payload_len == sizeof(test_data));
    assert(memcmp(payload, test_data, sizeof(test_data)) == 0);

    transport_free(&server_ctx);

    printf("  test_all_channels_combined: OK (%zu bytes through 7 channels)\n",
           sizeof(test_data));
}

/* ------------------------------------------------------------------ */
/* Test 7: Config defaults consistency                                   */
/* ------------------------------------------------------------------ */

static void test_config_defaults(void)
{
    client_config_t ccfg;
    server_config_t scfg;

    config_client_defaults(&ccfg);
    config_server_defaults(&scfg);

    /* Domain should be single-subdomain: example.com */
    assert(strcmp(ccfg.domain, "example.com") == 0);
    assert(strcmp(scfg.domain, "example.com") == 0);

    /* Default channels should be set */
    assert(ccfg.active_channels != 0);
    assert(scfg.active_channels != 0);

    /* Intersection should produce working channels */
    {
        uint32_t negotiated = ccfg.active_channels & scfg.active_channels;
        assert(negotiated != 0);
    }

    printf("  test_config_defaults: OK (domain=%s, client_chans=0x%08x, "
           "server_chans=0x%08x)\n",
           ccfg.domain,
           (unsigned)ccfg.active_channels,
           (unsigned)scfg.active_channels);
}

/* ------------------------------------------------------------------ */
/* main                                                                 */
/* ------------------------------------------------------------------ */

int main(void)
{
    printf("test_integration: running...\n");

    test_syn_handshake();
    test_data_roundtrip_multichannel();
    test_data_roundtrip_cname_chain();
    test_data_roundtrip_ns_chain();
    test_upstream_downstream_pipeline();
    test_all_channels_combined();
    test_config_defaults();

    printf("test_integration: ALL PASS\n");
    return 0;
}
