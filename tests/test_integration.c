/*
 * test_integration.c — Comprehensive end-to-end integration test.
 *
 * Exercises the FULL pipeline that a real DNS tunnel session traverses,
 * without actual UDP sockets.  Covers:
 *
 *  1.  PSK encryption round-trip (crypto_encrypt → crypto_decrypt)
 *  2.  Random ISN (sequence numbers start at random values)
 *  3.  Channel negotiation (SYN bitmask → SYN-ACK intersection)
 *  4.  Multi-channel data round-trip (pack → DNS wire → parse → unpack)
 *  5.  CNAME chain round-trip with embedded transport data
 *  6.  NS referral chain round-trip with embedded transport data
 *  7.  Upstream FQDN encode/decode pipeline
 *  8.  Downstream multi-channel pipeline with ALL 7 channels
 *  9.  Query type rotation (verify different types are returned)
 *  10. Adaptive window (RTT update → window size change)
 *  11. Config defaults (PSK, lazy_mode, domain, channels)
 *  12. Session resume token generation
 *  13. Encrypted transport full pipeline (PSK → build → encrypt → wire →
 *      parse → decrypt → verify)
 */

#include "transport.h"
#include "channel.h"
#include "chain.h"
#include "dns_packet.h"
#include "encode.h"
#include "config.h"
#include "crypto.h"
#include "stealth.h"
#include "log.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <assert.h>
#include <inttypes.h>

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
/* Test 1: PSK encryption round-trip                                    */
/* ------------------------------------------------------------------ */

static void test_psk_encryption_roundtrip(void)
{
    const uint8_t psk[] = "MySecretKey123!";
    size_t psk_len = sizeof(psk) - 1;
    crypto_ctx_t enc_ctx;
    crypto_ctx_t dec_ctx;
    uint8_t plaintext[64];
    uint8_t ciphertext[128];
    uint8_t recovered[128];
    int enc_len;
    int dec_len;

    fill_seq(plaintext, sizeof(plaintext));

    /* Initialize both sides with the same PSK */
    crypto_init(&enc_ctx, psk, psk_len);
    crypto_init(&dec_ctx, psk, psk_len);

    assert(enc_ctx.enabled == 1);
    assert(dec_ctx.enabled == 1);

    /* Verify key derivation produces the same hash on both sides */
    assert(memcmp(enc_ctx.key_hash, dec_ctx.key_hash, 32) == 0);

    /* Verify crypto_derive_key matches what crypto_init stored */
    {
        uint8_t standalone_key[32];
        crypto_derive_key(psk, psk_len, standalone_key);
        assert(memcmp(enc_ctx.key_hash, standalone_key, 32) == 0);
    }

    /* Encrypt */
    enc_len = crypto_encrypt(&enc_ctx, plaintext, sizeof(plaintext),
                              ciphertext, sizeof(ciphertext));
    assert(enc_len == (int)(sizeof(plaintext) + CRYPTO_NONCE_SIZE));

    /* Ciphertext should differ from plaintext (nonce + XOR) */
    assert(memcmp(ciphertext + CRYPTO_NONCE_SIZE, plaintext,
                   sizeof(plaintext)) != 0);

    /* Decrypt */
    dec_len = crypto_decrypt(&dec_ctx, ciphertext, (size_t)enc_len,
                              recovered, sizeof(recovered));
    assert(dec_len == (int)sizeof(plaintext));
    assert(memcmp(recovered, plaintext, sizeof(plaintext)) == 0);

    /* Encrypt a second packet — nonce should increment */
    {
        uint8_t ct2[128];
        int enc_len2 = crypto_encrypt(&enc_ctx, plaintext, sizeof(plaintext),
                                       ct2, sizeof(ct2));
        assert(enc_len2 > 0);
        /* Nonce bytes differ between first and second packet */
        assert(ct2[0] != ciphertext[0] || ct2[1] != ciphertext[1]);
    }

    /* Disabled crypto should passthrough */
    {
        crypto_ctx_t disabled;
        uint8_t pass_out[128];
        crypto_init(&disabled, NULL, 0);
        assert(disabled.enabled == 0);
        enc_len = crypto_encrypt(&disabled, plaintext, sizeof(plaintext),
                                  pass_out, sizeof(pass_out));
        assert(enc_len == (int)sizeof(plaintext));
        assert(memcmp(pass_out, plaintext, sizeof(plaintext)) == 0);
    }

    printf("  test_psk_encryption_roundtrip: OK (64 bytes encrypted/decrypted)\n");
}

/* ------------------------------------------------------------------ */
/* Test 2: Random ISN (Initial Sequence Number)                         */
/* ------------------------------------------------------------------ */

static void test_random_isn(void)
{
    transport_ctx_t ctx1;
    transport_ctx_t ctx2;
    transport_ctx_t ctx3;

    transport_init(&ctx1);
    transport_init(&ctx2);
    transport_init(&ctx3);

    /* ISN should be non-deterministic — at least two of three must differ */
    assert(ctx1.next_seq != ctx2.next_seq || ctx2.next_seq != ctx3.next_seq);

    /* Build a packet and verify the header carries the random seq */
    {
        uint16_t isn = ctx1.next_seq;
        uint8_t pkt[256];
        uint8_t data[] = "isn-test";
        int pkt_len = transport_build_packet(&ctx1, 0x0001, TUNNEL_FLAG_DATA,
                                              data, sizeof(data) - 1,
                                              pkt, sizeof(pkt));
        assert(pkt_len > 0);

        tunnel_header_t hdr;
        const uint8_t *payload;
        size_t payload_len;
        err_t e = transport_parse_packet(pkt, (size_t)pkt_len,
                                          &hdr, &payload, &payload_len);
        assert(e == ERR_OK);
        /* seq_num in the packet should match the ISN that was set */
        assert(hdr.seq_num == isn);
    }

    {
        unsigned s1 = ctx1.next_seq, s2 = ctx2.next_seq, s3 = ctx3.next_seq;
        transport_free(&ctx1);
        transport_free(&ctx2);
        transport_free(&ctx3);
        printf("  test_random_isn: OK (ISNs: %u, %u, %u)\n", s1, s2, s3);
    }
}

/* ------------------------------------------------------------------ */
/* Test 3: Channel negotiation (SYN → SYN-ACK)                         */
/* ------------------------------------------------------------------ */

static void test_channel_negotiation(void)
{
    transport_ctx_t client_ctx;
    transport_ctx_t server_ctx;
    uint16_t        session_id = 0x0042;
    uint32_t        client_chans = CHAN_NAPTR | CHAN_CAA | CHAN_AUTH_NS |
                                   CHAN_SVCB_DATA;
    uint32_t        server_chans = CHAN_NAPTR | CHAN_SOA_DATA | CHAN_AUTH_NS |
                                   CHAN_SVCB_DATA;
    uint32_t        expected_neg = client_chans & server_chans;
    uint8_t         pkt[TUNNEL_HEADER_SIZE + TUNNEL_MAX_PAYLOAD];
    int             pkt_len;
    tunnel_header_t hdr;
    const uint8_t  *payload;
    size_t          payload_len;
    err_t           e;
    uint32_t        negotiated;

    /* Verify expected intersection: NAPTR | AUTH_NS | SVCB_DATA */
    assert(expected_neg == (CHAN_NAPTR | CHAN_AUTH_NS | CHAN_SVCB_DATA));

    /* Client builds SYN with 4-byte big-endian channel bitmask */
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

    /* Server parses SYN, computes intersection */
    e = transport_parse_packet(pkt, (size_t)pkt_len, &hdr, &payload, &payload_len);
    assert(e == ERR_OK);
    assert(hdr.flags & TUNNEL_FLAG_SYN);
    assert(!(hdr.flags & TUNNEL_FLAG_ACK));
    assert(hdr.session_id == session_id);
    assert(payload_len >= 4);

    {
        uint32_t cli = ((uint32_t)payload[0] << 24) |
                       ((uint32_t)payload[1] << 16) |
                       ((uint32_t)payload[2] <<  8) |
                        (uint32_t)payload[3];
        assert(cli == client_chans);
        negotiated = cli & server_chans;
        assert(negotiated == expected_neg);
    }

    /* Server builds SYN-ACK */
    transport_init(&server_ctx);
    server_ctx.active_channels = negotiated;
    {
        uint8_t ack_payload[4];
        ack_payload[0] = (uint8_t)(negotiated >> 24);
        ack_payload[1] = (uint8_t)((negotiated >> 16) & 0xFFU);
        ack_payload[2] = (uint8_t)((negotiated >>  8) & 0xFFU);
        ack_payload[3] = (uint8_t)(negotiated & 0xFFU);

        pkt_len = transport_build_packet(&server_ctx, session_id,
                                          TUNNEL_FLAG_SYN | TUNNEL_FLAG_ACK,
                                          ack_payload, 4,
                                          pkt, sizeof(pkt));
        assert(pkt_len > 0);
    }

    /* Client parses SYN-ACK, extracts negotiated bitmask */
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

    assert(client_ctx.active_channels == server_ctx.active_channels);

    transport_free(&client_ctx);
    transport_free(&server_ctx);

    printf("  test_channel_negotiation: OK (negotiated=0x%08x)\n",
           (unsigned)expected_neg);
}

/* ------------------------------------------------------------------ */
/* Test 4: Multi-channel data round-trip (NAPTR+CAA through DNS wire)   */
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

    /* Client: build DATA packet */
    transport_init(&client_ctx);
    client_ctx.active_channels = channels;
    pkt_len = transport_build_packet(&client_ctx, session_id,
                                      TUNNEL_FLAG_DATA | TUNNEL_FLAG_ACK,
                                      test_data, sizeof(test_data),
                                      pkt, sizeof(pkt));
    assert(pkt_len > 0);

    /* Server: build multi-channel response echoing the data */
    transport_init(&server_ctx);
    server_ctx.active_channels = channels;
    {
        uint8_t server_pkt[512];
        int     server_pkt_len;

        server_pkt_len = transport_build_packet(&server_ctx, session_id,
                                                 TUNNEL_FLAG_DATA | TUNNEL_FLAG_ACK,
                                                 test_data, sizeof(test_data),
                                                 server_pkt, sizeof(server_pkt));
        assert(server_pkt_len > 0);

        channel_buf_init(&cb, channels, DOMAIN);
        {
            int packed = channel_pack(&cb, server_pkt, (size_t)server_pkt_len);
            assert(packed > 0);
        }

        wire_len = dns_build_response_ext(0x1234, "x.t." DOMAIN,
                                           DNS_TYPE_TXT, &cb.resp,
                                           wire, sizeof(wire));
        assert(wire_len > 0);
    }

    /* Client: parse DNS wire → channel unpack → transport parse */
    e = dns_parse_response_full(wire, (size_t)wire_len, &parsed);
    assert(e == ERR_OK);

    flat_len = channel_unpack(&parsed, channels, flat, sizeof(flat));
    assert(flat_len > 0);

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
/* Test 5: CNAME chain round-trip                                       */
/* ------------------------------------------------------------------ */

static void test_cname_chain_roundtrip(void)
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

    /* Server builds transport packet and wraps in 3-hop CNAME chain */
    transport_init(&server_ctx);
    pkt_len = transport_build_packet(&server_ctx, session_id,
                                      TUNNEL_FLAG_DATA | TUNNEL_FLAG_ACK,
                                      test_data, sizeof(test_data),
                                      pkt, sizeof(pkt));
    assert(pkt_len > 0);

    wire_len = chain_build_cname(0x2222, "x.t." DOMAIN, DOMAIN,
                                  pkt, (size_t)pkt_len, 3,
                                  wire, sizeof(wire));
    assert(wire_len > 0);

    /* Client: parse DNS wire → CNAME chain → transport */
    e = dns_parse_response_full(wire, (size_t)wire_len, &parsed);
    assert(e == ERR_OK);

    chain_len = chain_parse_cname(&parsed, DOMAIN, chain_data, sizeof(chain_data));
    assert(chain_len > 0);

    e = transport_parse_packet(chain_data, (size_t)chain_len,
                                &hdr, &payload, &payload_len);
    assert(e == ERR_OK);
    assert(hdr.flags & TUNNEL_FLAG_DATA);
    assert(payload_len == sizeof(test_data));
    assert(memcmp(payload, test_data, sizeof(test_data)) == 0);

    transport_free(&server_ctx);

    printf("  test_cname_chain_roundtrip: OK (%zu bytes through 3-hop CNAME chain)\n",
           sizeof(test_data));
}

/* ------------------------------------------------------------------ */
/* Test 6: NS referral chain round-trip                                 */
/* ------------------------------------------------------------------ */

static void test_ns_referral_roundtrip(void)
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

    transport_init(&server_ctx);
    pkt_len = transport_build_packet(&server_ctx, session_id,
                                      TUNNEL_FLAG_DATA | TUNNEL_FLAG_ACK,
                                      test_data, sizeof(test_data),
                                      pkt, sizeof(pkt));
    assert(pkt_len > 0);

    wire_len = chain_build_ns_referral(0x3333, "x.t." DOMAIN, DOMAIN,
                                        pkt, (size_t)pkt_len, 2,
                                        wire, sizeof(wire));
    assert(wire_len > 0);

    e = dns_parse_response_full(wire, (size_t)wire_len, &parsed);
    assert(e == ERR_OK);

    chain_len = chain_parse_ns_referral(&parsed, DOMAIN,
                                          chain_data, sizeof(chain_data));
    assert(chain_len > 0);

    e = transport_parse_packet(chain_data, (size_t)chain_len,
                                &hdr, &payload, &payload_len);
    assert(e == ERR_OK);
    assert(hdr.flags & TUNNEL_FLAG_DATA);
    assert(payload_len == sizeof(test_data));
    assert(memcmp(payload, test_data, sizeof(test_data)) == 0);

    transport_free(&server_ctx);

    printf("  test_ns_referral_roundtrip: OK (%zu bytes through 2-NS referral)\n",
           sizeof(test_data));
}

/* ------------------------------------------------------------------ */
/* Test 7: Upstream FQDN encode/decode pipeline                         */
/* ------------------------------------------------------------------ */

static void test_upstream_fqdn_pipeline(void)
{
    transport_ctx_t  client_ctx;
    transport_ctx_t  server_ctx;
    uint16_t         session_id = 0x00CC;
    uint32_t         channels   = CHAN_NAPTR;
    uint8_t          test_data[] = "Hello, tunnel!";
    size_t           test_data_len = sizeof(test_data) - 1;

    /* === UPSTREAM: client → FQDN → server === */

    /* Client: build transport DATA, encode into FQDN */
    transport_init(&client_ctx);
    client_ctx.active_channels = channels;

    uint8_t up_pkt[512];
    int up_pkt_len = transport_build_packet(&client_ctx, session_id,
                                             TUNNEL_FLAG_DATA,
                                             test_data, test_data_len,
                                             up_pkt, sizeof(up_pkt));
    assert(up_pkt_len > 0);

    char labels[512];
    int llen = encode_to_labels(up_pkt, (size_t)up_pkt_len,
                                 labels, sizeof(labels), ENCODE_BASE32);
    assert(llen > 0);

    char fqdn[768];
    int fqdn_len = snprintf(fqdn, sizeof(fqdn), "%s.%04x.t.%s",
                             labels, session_id, DOMAIN);
    assert(fqdn_len > 0 && (size_t)fqdn_len < sizeof(fqdn));

    /* Server: parse FQDN → decode → extract transport */
    {
        uint16_t parsed_sid;
        char     encoded[512];
        int r = parse_tunnel_fqdn(fqdn, DOMAIN, &parsed_sid,
                                   encoded, sizeof(encoded));
        assert(r == 0);
        assert(parsed_sid == session_id);

        uint8_t decoded[512];
        int dec_len = decode_from_labels(encoded, strlen(encoded),
                                          decoded, sizeof(decoded),
                                          ENCODE_BASE32);
        assert(dec_len > 0);

        tunnel_header_t hdr;
        const uint8_t  *payload;
        size_t          payload_len;
        err_t e = transport_parse_packet(decoded, (size_t)dec_len,
                                          &hdr, &payload, &payload_len);
        assert(e == ERR_OK);
        assert(hdr.flags & TUNNEL_FLAG_DATA);
        assert(payload_len == test_data_len);
        assert(memcmp(payload, test_data, test_data_len) == 0);
    }

    /* === DOWNSTREAM: server → channel → DNS wire → client === */

    transport_init(&server_ctx);
    server_ctx.active_channels = channels;

    uint8_t dn_pkt[512];
    int dn_pkt_len = transport_build_packet(&server_ctx, session_id,
                                             TUNNEL_FLAG_DATA | TUNNEL_FLAG_ACK,
                                             test_data, test_data_len,
                                             dn_pkt, sizeof(dn_pkt));
    assert(dn_pkt_len > 0);

    channel_buf_t cb;
    channel_buf_init(&cb, channels, DOMAIN);
    {
        int packed = channel_pack(&cb, dn_pkt, (size_t)dn_pkt_len);
        assert(packed > 0);
    }

    uint8_t wire[4096];
    int wire_len = dns_build_response_ext(0x5678, fqdn, DNS_TYPE_TXT,
                                           &cb.resp, wire, sizeof(wire));
    assert(wire_len > 0);

    dns_parsed_response_t parsed;
    err_t e = dns_parse_response_full(wire, (size_t)wire_len, &parsed);
    assert(e == ERR_OK);

    uint8_t flat[4096];
    int flat_len = channel_unpack(&parsed, channels, flat, sizeof(flat));
    assert(flat_len > 0);

    {
        tunnel_header_t hdr;
        const uint8_t  *payload;
        size_t          payload_len;

        e = transport_parse_packet(flat, (size_t)flat_len,
                                    &hdr, &payload, &payload_len);
        assert(e == ERR_OK);
        assert(hdr.flags & TUNNEL_FLAG_DATA);
        assert(payload_len == test_data_len);
        assert(memcmp(payload, test_data, test_data_len) == 0);
    }

    transport_free(&client_ctx);
    transport_free(&server_ctx);

    printf("  test_upstream_fqdn_pipeline: OK (%zu bytes both directions)\n",
           test_data_len);
}

/* ------------------------------------------------------------------ */
/* Test 8: Downstream with all working DNS channels                     */
/* ------------------------------------------------------------------ */

static void test_all_working_channels(void)
{
    transport_ctx_t  server_ctx;
    uint16_t         session_id = 0x00DD;
    uint32_t         channels   = CHAN_NAPTR | CHAN_CAA | CHAN_SOA_DATA |
                                  CHAN_SRV | CHAN_AUTH_NS;
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

    /* Server: build transport → pack all working channels → DNS wire */
    transport_init(&server_ctx);
    server_ctx.active_channels = channels;

    pkt_len = transport_build_packet(&server_ctx, session_id,
                                      TUNNEL_FLAG_DATA | TUNNEL_FLAG_ACK,
                                      test_data, sizeof(test_data),
                                      pkt, sizeof(pkt));
    assert(pkt_len > 0);

    channel_buf_init(&cb, channels, DOMAIN);
    {
        int packed = channel_pack(&cb, pkt, (size_t)pkt_len);
        assert(packed > 0);
    }

    wire_len = dns_build_response_ext(0xABCD, "x.t." DOMAIN,
                                       DNS_TYPE_TXT, &cb.resp,
                                       wire, sizeof(wire));
    assert(wire_len > 0);

    /* Client: parse → unpack → transport verify */
    e = dns_parse_response_full(wire, (size_t)wire_len, &parsed);
    assert(e == ERR_OK);

    flat_len = channel_unpack(&parsed, channels, flat, sizeof(flat));
    assert(flat_len > 0);

    e = transport_parse_packet(flat, (size_t)flat_len, &hdr, &payload, &payload_len);
    assert(e == ERR_OK);
    assert(hdr.flags & TUNNEL_FLAG_DATA);
    assert(payload_len == sizeof(test_data));
    assert(memcmp(payload, test_data, sizeof(test_data)) == 0);

    transport_free(&server_ctx);

    printf("  test_all_working_channels: OK (%zu bytes through 5 channels)\n",
           sizeof(test_data));
}

/* ------------------------------------------------------------------ */
/* Test 9: Query type rotation                                          */
/* ------------------------------------------------------------------ */

static void test_query_type_rotation(void)
{
    transport_ctx_t ctx;
    int first_type;
    int seen_different = 0;
    int i;

    transport_init(&ctx);

    first_type = transport_next_query_type(&ctx);
    assert(first_type > 0);

    /* Pump enough queries to force at least one rotation.
     * rotate_interval starts at 50, max is 120 (from transport.c).
     * After 121 queries we're guaranteed at least one rotation. */
    for (i = 1; i < 121; i++) {
        int qt = transport_next_query_type(&ctx);
        assert(qt > 0);
        if (qt != first_type) {
            seen_different = 1;
        }
    }
    assert(seen_different);

    /* Verify returned types are valid DNS query types */
    {
        int qt = transport_next_query_type(&ctx);
        assert(qt == DNS_TYPE_TXT  || qt == DNS_TYPE_AAAA ||
               qt == DNS_TYPE_A    || qt == DNS_TYPE_SRV  ||
               qt == DNS_TYPE_NAPTR);
    }

    transport_free(&ctx);

    printf("  test_query_type_rotation: OK (first=%d, rotated after <=120 queries)\n",
           first_type);
}

/* ------------------------------------------------------------------ */
/* Test 10: Adaptive window size based on RTT                           */
/* ------------------------------------------------------------------ */

static void test_adaptive_window(void)
{
    transport_ctx_t ctx;
    int initial_window;
    int i;

    transport_init(&ctx);
    initial_window = ctx.window_size;
    assert(initial_window == WINDOW_SIZE_DEFAULT);
    assert(ctx.rtt_ewma_us == 200000);

    /* Feed improving (low) RTT samples → window should grow */
    for (i = 0; i < 40; i++) {
        transport_update_rtt(&ctx, 50000);  /* 50ms, much less than 200ms */
    }
    assert(ctx.window_size > initial_window);
    assert(ctx.window_size <= 32);

    /* Feed worsening (high) RTT samples → window should shrink */
    {
        int peak_window = ctx.window_size;
        for (i = 0; i < 60; i++) {
            transport_update_rtt(&ctx, 2000000);  /* 2000ms, very high */
        }
        assert(ctx.window_size < peak_window);
        assert(ctx.window_size >= 2);
    }

    transport_free(&ctx);

    printf("  test_adaptive_window: OK (default=%d, grew then shrank)\n",
           initial_window);
}

/* ------------------------------------------------------------------ */
/* Test 11: Config defaults                                             */
/* ------------------------------------------------------------------ */

static void test_config_defaults(void)
{
    client_config_t ccfg;
    server_config_t scfg;

    config_client_defaults(&ccfg);
    config_server_defaults(&scfg);

    /* Domain should be single-subdomain format */
    assert(strcmp(ccfg.domain, "example.com") == 0);
    assert(strcmp(scfg.domain, "example.com") == 0);

    /* Default channels should be set */
    assert(ccfg.active_channels != 0);
    assert(scfg.active_channels != 0);

    /* Intersection should produce working channels */
    {
        uint32_t negotiated = ccfg.active_channels & scfg.active_channels;
        assert(negotiated != 0);
        /* Core channels must be present in the intersection */
        assert(negotiated & CHAN_NAPTR);
    }

    /* PSK defaults to empty / disabled */
    assert(ccfg.psk_len == 0);
    assert(scfg.psk_len == 0);

    /* Lazy mode defaults to enabled */
    assert(ccfg.lazy_mode == 1);
    assert(scfg.lazy_mode == 1);

    /* Chain depths are sensible */
    assert(ccfg.cname_chain_depth >= 1 && ccfg.cname_chain_depth <= CHAIN_MAX_DEPTH);
    assert(ccfg.ns_chain_depth >= 1 && ccfg.ns_chain_depth <= 4);
    assert(scfg.cname_chain_depth == ccfg.cname_chain_depth);
    assert(scfg.ns_chain_depth == ccfg.ns_chain_depth);

    /* Client listen defaults */
    assert(ccfg.listen_port == 1080);
    assert(strcmp(ccfg.listen_addr, "127.0.0.1") == 0);

    /* Server bind defaults */
    assert(scfg.bind_port == 53);

    printf("  test_config_defaults: OK (domain=%s, psk_len=0, lazy=%d, "
           "client_chans=0x%08x)\n",
           ccfg.domain, ccfg.lazy_mode,
           (unsigned)ccfg.active_channels);
}

/* ------------------------------------------------------------------ */
/* Test 12: Session resume token generation                             */
/* ------------------------------------------------------------------ */

static void test_session_resume_token(void)
{
    transport_ctx_t ctx1;
    transport_ctx_t ctx2;
    int all_zero;
    size_t i;

    transport_init(&ctx1);
    assert(ctx1.has_session_token == 0);

    /* Generate token */
    transport_generate_token(&ctx1);
    assert(ctx1.has_session_token == 1);

    /* Token should not be all zeros (random fill) */
    all_zero = 1;
    for (i = 0; i < SESSION_TOKEN_SIZE; i++) {
        if (ctx1.session_token[i] != 0) { all_zero = 0; break; }
    }
    assert(!all_zero);

    /* Two tokens should differ */
    transport_init(&ctx2);
    transport_generate_token(&ctx2);
    assert(memcmp(ctx1.session_token, ctx2.session_token,
                   SESSION_TOKEN_SIZE) != 0);

    /* Token can be embedded in a SYN payload for session resume */
    {
        uint8_t syn_payload[4 + SESSION_TOKEN_SIZE];
        uint32_t chans = CHAN_NAPTR;
        syn_payload[0] = (uint8_t)(chans >> 24);
        syn_payload[1] = (uint8_t)((chans >> 16) & 0xFFU);
        syn_payload[2] = (uint8_t)((chans >>  8) & 0xFFU);
        syn_payload[3] = (uint8_t)(chans & 0xFFU);
        memcpy(syn_payload + 4, ctx1.session_token, SESSION_TOKEN_SIZE);

        uint8_t pkt[256];
        int pkt_len = transport_build_packet(&ctx1, 0x00EE,
                                              TUNNEL_FLAG_SYN,
                                              syn_payload, sizeof(syn_payload),
                                              pkt, sizeof(pkt));
        assert(pkt_len > 0);

        tunnel_header_t hdr;
        const uint8_t *payload;
        size_t payload_len;
        err_t e = transport_parse_packet(pkt, (size_t)pkt_len,
                                          &hdr, &payload, &payload_len);
        assert(e == ERR_OK);
        assert(payload_len == sizeof(syn_payload));
        assert(memcmp(payload + 4, ctx1.session_token,
                       SESSION_TOKEN_SIZE) == 0);
    }

    printf("  test_session_resume_token: OK (token=%02x%02x%02x%02x...)\n",
           ctx1.session_token[0], ctx1.session_token[1],
           ctx1.session_token[2], ctx1.session_token[3]);

    transport_free(&ctx1);
    transport_free(&ctx2);
}

/* ------------------------------------------------------------------ */
/* Test 13: Encrypted transport full pipeline                           */
/* ------------------------------------------------------------------ */

static void test_encrypted_transport_pipeline(void)
{
    const uint8_t psk[] = "tunnel-secret-2024";
    size_t psk_len = sizeof(psk) - 1;
    transport_ctx_t client_ctx;
    transport_ctx_t server_ctx;
    uint16_t session_id = 0x00FF;
    uint32_t channels = CHAN_NAPTR | CHAN_CAA;
    uint8_t  test_data[80];
    uint8_t  pkt[512];
    int      pkt_len;
    uint8_t  enc_buf[512];
    int      enc_len;

    fill_seq(test_data, sizeof(test_data));

    /* Client: set PSK, build packet, encrypt */
    transport_init(&client_ctx);
    transport_set_psk(&client_ctx, psk, psk_len);
    assert(client_ctx.crypto.enabled == 1);

    pkt_len = transport_build_packet(&client_ctx, session_id,
                                      TUNNEL_FLAG_DATA,
                                      test_data, sizeof(test_data),
                                      pkt, sizeof(pkt));
    assert(pkt_len > 0);

    enc_len = crypto_encrypt(&client_ctx.crypto, pkt, (size_t)pkt_len,
                              enc_buf, sizeof(enc_buf));
    assert(enc_len == pkt_len + (int)CRYPTO_NONCE_SIZE);

    /* Server: set PSK, decrypt, parse transport, build response */
    transport_init(&server_ctx);
    transport_set_psk(&server_ctx, psk, psk_len);
    server_ctx.active_channels = channels;

    {
        uint8_t dec_buf[512];
        int dec_len = crypto_decrypt(&server_ctx.crypto,
                                      enc_buf, (size_t)enc_len,
                                      dec_buf, sizeof(dec_buf));
        assert(dec_len == pkt_len);

        tunnel_header_t hdr;
        const uint8_t *payload;
        size_t payload_len;
        err_t e = transport_parse_packet(dec_buf, (size_t)dec_len,
                                          &hdr, &payload, &payload_len);
        assert(e == ERR_OK);
        assert(hdr.flags & TUNNEL_FLAG_DATA);
        assert(payload_len == sizeof(test_data));
        assert(memcmp(payload, test_data, sizeof(test_data)) == 0);

        /* Server: build encrypted response through channel pipeline */
        uint8_t resp_pkt[512];
        int resp_pkt_len = transport_build_packet(&server_ctx, session_id,
                                                   TUNNEL_FLAG_DATA | TUNNEL_FLAG_ACK,
                                                   test_data, sizeof(test_data),
                                                   resp_pkt, sizeof(resp_pkt));
        assert(resp_pkt_len > 0);

        /* Encrypt server response */
        uint8_t resp_enc[512];
        int resp_enc_len = crypto_encrypt(&server_ctx.crypto,
                                           resp_pkt, (size_t)resp_pkt_len,
                                           resp_enc, sizeof(resp_enc));
        assert(resp_enc_len > 0);

        /* Pack encrypted data into channels */
        channel_buf_t cb;
        channel_buf_init(&cb, channels, DOMAIN);
        {
            int packed = channel_pack(&cb, resp_enc, (size_t)resp_enc_len);
            assert(packed > 0);
        }

        /* Build DNS wire */
        uint8_t wire[8192];
        int wire_len = dns_build_response_ext(0xBEEF, "x.t." DOMAIN,
                                               DNS_TYPE_TXT, &cb.resp,
                                               wire, sizeof(wire));
        assert(wire_len > 0);

        /* Client: parse DNS wire → unpack → decrypt → parse transport */
        dns_parsed_response_t parsed;
        e = dns_parse_response_full(wire, (size_t)wire_len, &parsed);
        assert(e == ERR_OK);

        uint8_t flat[8192];
        int flat_len = channel_unpack(&parsed, channels, flat, sizeof(flat));
        assert(flat_len > 0);

        uint8_t client_dec[512];
        int client_dec_len = crypto_decrypt(&client_ctx.crypto,
                                             flat, (size_t)flat_len,
                                             client_dec, sizeof(client_dec));
        assert(client_dec_len > 0);

        tunnel_header_t rhdr;
        const uint8_t *rpayload;
        size_t rpayload_len;
        e = transport_parse_packet(client_dec, (size_t)client_dec_len,
                                    &rhdr, &rpayload, &rpayload_len);
        assert(e == ERR_OK);
        assert(rhdr.flags & TUNNEL_FLAG_DATA);
        assert(rpayload_len == sizeof(test_data));
        assert(memcmp(rpayload, test_data, sizeof(test_data)) == 0);
    }

    transport_free(&client_ctx);
    transport_free(&server_ctx);

    printf("  test_encrypted_transport_pipeline: OK (%zu bytes encrypted both ways)\n",
           sizeof(test_data));
}

/* ------------------------------------------------------------------ */
/* Test 14: Stealth entropy measurement on tunnel data                  */
/* ------------------------------------------------------------------ */

static void test_stealth_entropy(void)
{
    uint8_t random_data[256];
    uint8_t uniform_data[256];
    double  rand_entropy;
    double  uniform_entropy;
    size_t  i;

    /* Random data should have high entropy */
    stealth_random_bytes(random_data, sizeof(random_data));
    rand_entropy = stealth_entropy(random_data, sizeof(random_data));
    assert(rand_entropy > 5.0);  /* Random data ≈ 7-8 bits */
    assert(rand_entropy <= 8.0);

    /* Uniform (repetitive) data should have low entropy */
    for (i = 0; i < sizeof(uniform_data); i++) {
        uniform_data[i] = 0xAA;
    }
    uniform_entropy = stealth_entropy(uniform_data, sizeof(uniform_data));
    assert(uniform_entropy < 1.0);  /* Single byte value = 0 bits */

    /* Encoded tunnel data should have measurable entropy */
    {
        transport_ctx_t ctx;
        uint8_t test_data[64];
        uint8_t pkt[256];
        int pkt_len;
        double pkt_entropy;

        fill_seq(test_data, sizeof(test_data));
        transport_init(&ctx);
        pkt_len = transport_build_packet(&ctx, 0x1234, TUNNEL_FLAG_DATA,
                                          test_data, sizeof(test_data),
                                          pkt, sizeof(pkt));
        assert(pkt_len > 0);

        pkt_entropy = stealth_entropy(pkt, (size_t)pkt_len);
        assert(pkt_entropy > 2.0);  /* Structured but varied data */

        transport_free(&ctx);
    }

    printf("  test_stealth_entropy: OK (random=%.2f, uniform=%.2f)\n",
           rand_entropy, uniform_entropy);
}

/* ------------------------------------------------------------------ */
/* Test 15: Full session lifecycle (SYN → data → FIN)                   */
/* ------------------------------------------------------------------ */

static void test_full_session_lifecycle(void)
{
    transport_ctx_t client_ctx;
    transport_ctx_t server_ctx;
    uint16_t session_id = 0x00EE;
    uint32_t client_chans = CHAN_NAPTR | CHAN_CAA | CHAN_AUTH_NS;
    uint32_t server_chans = CHAN_NAPTR | CHAN_CAA | CHAN_SRV;
    uint32_t negotiated;
    uint8_t  pkt[512];
    int      pkt_len;

    transport_init(&client_ctx);
    transport_init(&server_ctx);

    /* Phase 1: SYN */
    {
        uint8_t syn_pl[4];
        syn_pl[0] = (uint8_t)(client_chans >> 24);
        syn_pl[1] = (uint8_t)((client_chans >> 16) & 0xFFU);
        syn_pl[2] = (uint8_t)((client_chans >>  8) & 0xFFU);
        syn_pl[3] = (uint8_t)(client_chans & 0xFFU);

        pkt_len = transport_build_packet(&client_ctx, session_id,
                                          TUNNEL_FLAG_SYN,
                                          syn_pl, 4, pkt, sizeof(pkt));
        assert(pkt_len > 0);

        tunnel_header_t hdr;
        const uint8_t *payload;
        size_t payload_len;
        err_t e = transport_parse_packet(pkt, (size_t)pkt_len,
                                          &hdr, &payload, &payload_len);
        assert(e == ERR_OK);
        assert(hdr.flags == TUNNEL_FLAG_SYN);

        uint32_t cli = ((uint32_t)payload[0] << 24) |
                       ((uint32_t)payload[1] << 16) |
                       ((uint32_t)payload[2] <<  8) |
                        (uint32_t)payload[3];
        negotiated = cli & server_chans;
    }

    /* Phase 2: SYN-ACK */
    {
        uint8_t ack_pl[4];
        ack_pl[0] = (uint8_t)(negotiated >> 24);
        ack_pl[1] = (uint8_t)((negotiated >> 16) & 0xFFU);
        ack_pl[2] = (uint8_t)((negotiated >>  8) & 0xFFU);
        ack_pl[3] = (uint8_t)(negotiated & 0xFFU);

        pkt_len = transport_build_packet(&server_ctx, session_id,
                                          TUNNEL_FLAG_SYN | TUNNEL_FLAG_ACK,
                                          ack_pl, 4, pkt, sizeof(pkt));
        assert(pkt_len > 0);

        tunnel_header_t hdr;
        const uint8_t *payload;
        size_t payload_len;
        err_t e = transport_parse_packet(pkt, (size_t)pkt_len,
                                          &hdr, &payload, &payload_len);
        assert(e == ERR_OK);
        assert(hdr.flags == (TUNNEL_FLAG_SYN | TUNNEL_FLAG_ACK));

        client_ctx.active_channels = negotiated;
        server_ctx.active_channels = negotiated;
    }

    /* Phase 3: DATA exchange through full channel pipeline */
    {
        uint8_t test_data[] = "session-lifecycle-test-payload";
        size_t test_data_len = sizeof(test_data) - 1;
        uint8_t data_pkt[512];
        int data_pkt_len;

        data_pkt_len = transport_build_packet(&server_ctx, session_id,
                                               TUNNEL_FLAG_DATA | TUNNEL_FLAG_ACK,
                                               test_data, test_data_len,
                                               data_pkt, sizeof(data_pkt));
        assert(data_pkt_len > 0);

        channel_buf_t cb;
        channel_buf_init(&cb, negotiated, DOMAIN);
        int packed = channel_pack(&cb, data_pkt, (size_t)data_pkt_len);
        assert(packed > 0);

        uint8_t wire[8192];
        int wire_len = dns_build_response_ext(0xF00D, "x.t." DOMAIN,
                                               DNS_TYPE_TXT, &cb.resp,
                                               wire, sizeof(wire));
        assert(wire_len > 0);

        dns_parsed_response_t parsed;
        err_t e = dns_parse_response_full(wire, (size_t)wire_len, &parsed);
        assert(e == ERR_OK);

        uint8_t flat[8192];
        int flat_len = channel_unpack(&parsed, negotiated, flat, sizeof(flat));
        assert(flat_len > 0);

        tunnel_header_t hdr;
        const uint8_t *payload;
        size_t payload_len;
        e = transport_parse_packet(flat, (size_t)flat_len,
                                    &hdr, &payload, &payload_len);
        assert(e == ERR_OK);
        assert(hdr.flags & TUNNEL_FLAG_DATA);
        assert(payload_len == test_data_len);
        assert(memcmp(payload, test_data, test_data_len) == 0);
    }

    /* Phase 4: FIN */
    {
        pkt_len = transport_build_packet(&client_ctx, session_id,
                                          TUNNEL_FLAG_FIN,
                                          NULL, 0, pkt, sizeof(pkt));
        assert(pkt_len > 0);

        tunnel_header_t hdr;
        const uint8_t *payload;
        size_t payload_len;
        err_t e = transport_parse_packet(pkt, (size_t)pkt_len,
                                          &hdr, &payload, &payload_len);
        assert(e == ERR_OK);
        assert(hdr.flags & TUNNEL_FLAG_FIN);
        assert(payload_len == 0);
    }

    transport_free(&client_ctx);
    transport_free(&server_ctx);

    printf("  test_full_session_lifecycle: OK (SYN→SYN-ACK→DATA→FIN, "
           "negotiated=0x%08x)\n", (unsigned)negotiated);
}

/* ------------------------------------------------------------------ */
/* main                                                                 */
/* ------------------------------------------------------------------ */

int main(void)
{
    log_set_level(LOG_ERROR);

    printf("test_integration: running...\n");

    test_psk_encryption_roundtrip();
    test_random_isn();
    test_channel_negotiation();
    test_data_roundtrip_multichannel();
    test_cname_chain_roundtrip();
    test_ns_referral_roundtrip();
    test_upstream_fqdn_pipeline();
    test_all_working_channels();
    test_query_type_rotation();
    test_adaptive_window();
    test_config_defaults();
    test_session_resume_token();
    test_encrypted_transport_pipeline();
    test_stealth_entropy();
    test_full_session_lifecycle();

    printf("test_integration: ALL PASS\n");
    return 0;
}
