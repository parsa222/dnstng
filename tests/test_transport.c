#include "transport.h"
#include <stdio.h>
#include <string.h>
#include <assert.h>
#include <stdint.h>

static void test_build_parse_roundtrip(void)
{
    transport_ctx_t  ctx;
    uint8_t          pkt[TUNNEL_HEADER_SIZE + TUNNEL_MAX_PAYLOAD];
    int              pkt_len;
    tunnel_header_t  hdr;
    const uint8_t   *payload;
    size_t           payload_len;
    static const uint8_t data[] = { 0x01, 0x02, 0x03, 0x04, 0x05 };
    err_t            e;

    transport_init(&ctx);

    pkt_len = transport_build_packet(&ctx, 0x1234U, TUNNEL_FLAG_DATA,
                                      data, sizeof(data),
                                      pkt, sizeof(pkt));
    assert(pkt_len > 0);
    assert((size_t)pkt_len == TUNNEL_HEADER_SIZE + sizeof(data));
    printf("  built packet: len=%d\n", pkt_len);

    e = transport_parse_packet(pkt, (size_t)pkt_len,
                                &hdr, &payload, &payload_len);
    assert(e == ERR_OK);
    assert(hdr.session_id == 0x1234U);
    assert(hdr.flags == TUNNEL_FLAG_DATA);
    assert(payload_len == sizeof(data));
    assert(memcmp(payload, data, sizeof(data)) == 0);
    printf("  parsed: session_id=0x%04x flags=0x%02x payload_len=%zu\n",
           hdr.session_id, hdr.flags, payload_len);

    transport_free(&ctx);
}

static void test_crc_verification(void)
{
    transport_ctx_t  ctx;
    uint8_t          pkt[TUNNEL_HEADER_SIZE + 10];
    int              pkt_len;
    int              ok;
    static const uint8_t data[] = { 0xAA, 0xBB, 0xCC };

    transport_init(&ctx);

    pkt_len = transport_build_packet(&ctx, 0x0001U, TUNNEL_FLAG_ACK,
                                      data, sizeof(data),
                                      pkt, sizeof(pkt));
    assert(pkt_len > 0);

    ok = transport_verify_checksum(pkt, (size_t)pkt_len);
    assert(ok == 1);
    printf("  CRC valid: ok\n");

    /* Corrupt a byte */
    pkt[TUNNEL_HEADER_SIZE + 1] ^= 0xFF;
    ok = transport_verify_checksum(pkt, (size_t)pkt_len);
    assert(ok == 0);
    printf("  CRC detects corruption: ok\n");

    transport_free(&ctx);
}

static void test_seq_increment(void)
{
    transport_ctx_t ctx;
    uint8_t         pkt[TUNNEL_HEADER_SIZE];
    int             pkt_len;
    tunnel_header_t hdr;
    const uint8_t  *payload;
    size_t          payload_len;
    uint16_t        initial_seq;

    transport_init(&ctx);
    initial_seq = ctx.next_seq;  /* Random ISN (dnscat2-inspired) */

    pkt_len = transport_build_packet(&ctx, 1U, TUNNEL_FLAG_POLL,
                                      NULL, 0, pkt, sizeof(pkt));
    assert(pkt_len > 0);
    transport_parse_packet(pkt, (size_t)pkt_len, &hdr, &payload, &payload_len);
    assert(hdr.seq_num == initial_seq);
    assert(ctx.next_seq == (uint16_t)(initial_seq + 1));

    pkt_len = transport_build_packet(&ctx, 1U, TUNNEL_FLAG_POLL,
                                      NULL, 0, pkt, sizeof(pkt));
    assert(pkt_len > 0);
    transport_parse_packet(pkt, (size_t)pkt_len, &hdr, &payload, &payload_len);
    assert(hdr.seq_num == (uint16_t)(initial_seq + 1));
    assert(ctx.next_seq == (uint16_t)(initial_seq + 2));

    printf("  seq numbers: %u, %u (random ISN) as expected\n",
           initial_seq, (uint16_t)(initial_seq + 1));
    transport_free(&ctx);
}

static void test_ring_buffer_enqueue(void)
{
    transport_ctx_t  ctx;
    uint8_t          pkt[TUNNEL_HEADER_SIZE + 4];
    static const uint8_t data[] = { 0x11, 0x22, 0x33, 0x44 };
    int              pkt_len;
    err_t            e;
    uint16_t         initial_seq;
    size_t           slot_idx;

    transport_init(&ctx);
    initial_seq = ctx.next_seq;  /* Random ISN */
    slot_idx    = initial_seq % RING_BUFFER_SIZE;

    pkt_len = transport_build_packet(&ctx, 0x0002U, TUNNEL_FLAG_DATA,
                                      data, sizeof(data),
                                      pkt, sizeof(pkt));
    assert(pkt_len > 0);

    /* The slot should already be in the ring from build_packet */
    assert(ctx.slots[slot_idx].in_use == 1);
    assert(ctx.slots[slot_idx].seq == initial_seq);

    /* Now enqueue a synthetic packet at a different slot */
    e = transport_enqueue(&ctx, pkt, (size_t)pkt_len, 5);
    assert(e == ERR_OK);
    assert(ctx.slots[5 % RING_BUFFER_SIZE].in_use == 1);
    assert(ctx.slots[5 % RING_BUFFER_SIZE].seq == 5);

    /* ACK frees slots */
    transport_ack(&ctx, initial_seq); /* ack the first packet */
    assert(ctx.slots[slot_idx].in_use == 0);
    printf("  ring buffer enqueue/ack: ok\n");

    transport_free(&ctx);
}

typedef struct {
    int count;
} retransmit_count_t;

static void retransmit_cb(const uint8_t *pkt, size_t len, void *ud)
{
    retransmit_count_t *rc = (retransmit_count_t *)ud;
    (void)pkt;
    (void)len;
    rc->count++;
}

static void test_retransmit(void)
{
    transport_ctx_t    ctx;
    uint8_t            pkt[TUNNEL_HEADER_SIZE];
    int                pkt_len;
    retransmit_count_t rc;
    uint16_t           initial_seq;
    size_t             slot_idx;

    transport_init(&ctx);
    initial_seq = ctx.next_seq;
    slot_idx    = initial_seq % RING_BUFFER_SIZE;

    pkt_len = transport_build_packet(&ctx, 1U, TUNNEL_FLAG_DATA,
                                      NULL, 0, pkt, sizeof(pkt));
    assert(pkt_len > 0);

    /* Force slot to appear old */
    ctx.slots[slot_idx].send_time_ms = 0;

    rc.count = 0;
    transport_check_retransmit(&ctx, 5000ULL, 1000ULL,
                                 retransmit_cb, &rc);
    assert(rc.count == 1);
    printf("  retransmit triggered: ok (count=%d)\n", rc.count);

    /* After retransmit, send_time_ms updated - should NOT retransmit immediately */
    rc.count = 0;
    transport_check_retransmit(&ctx, 5000ULL, 1000ULL,
                                 retransmit_cb, &rc);
    assert(rc.count == 0);
    printf("  no re-retransmit immediately: ok\n");

    transport_free(&ctx);
}

static void test_parse_too_short(void)
{
    uint8_t          buf[4];
    tunnel_header_t  hdr;
    const uint8_t   *payload;
    size_t           payload_len;
    err_t            e;

    memset(buf, 0, sizeof(buf));
    e = transport_parse_packet(buf, sizeof(buf), &hdr, &payload, &payload_len);
    assert(e == ERR_PROTO);
    printf("  short packet rejected: ok\n");
}

int main(void)
{
    printf("test_transport: running...\n");

    printf("[1] build/parse roundtrip\n");
    test_build_parse_roundtrip();

    printf("[2] CRC verification\n");
    test_crc_verification();

    printf("[3] sequence number increment\n");
    test_seq_increment();

    printf("[4] ring buffer enqueue/ack\n");
    test_ring_buffer_enqueue();

    printf("[5] retransmit logic\n");
    test_retransmit();

    printf("[6] short packet rejected\n");
    test_parse_too_short();

    printf("test_transport: ALL PASS\n");
    return 0;
}
