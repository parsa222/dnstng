#include "transport.h"
#include "util.h"
#include "stealth.h"
#include "dns_packet.h"
#include <string.h>
#include <time.h>

/* ------------------------------------------------------------------ */
/* Time utility                                                         */
/* ------------------------------------------------------------------ */

uint64_t get_time_ms(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000ULL + (uint64_t)(ts.tv_nsec / 1000000L);
}

/* ------------------------------------------------------------------ */
/* Query type rotation table (like iodine's -T option)                  */
/* ------------------------------------------------------------------ */

static const uint16_t QUERY_TYPES[] = {
    DNS_TYPE_TXT,   /* Most bandwidth */
    DNS_TYPE_AAAA,  /* Reasonable bandwidth */
    DNS_TYPE_A,     /* Low bandwidth but always works */
    DNS_TYPE_SRV,   /* Good bandwidth, sometimes filtered */
    DNS_TYPE_NAPTR, /* Often allowed */
};
#define NUM_QUERY_TYPES (sizeof(QUERY_TYPES) / sizeof(QUERY_TYPES[0]))

/* ------------------------------------------------------------------ */
/* Lifecycle                                                            */
/* ------------------------------------------------------------------ */

err_t transport_init(transport_ctx_t *ctx)
{
    if (!ctx) {
        return ERR_INVAL;
    }
    memset(ctx, 0, sizeof(*ctx));

    /* Random ISN (dnscat2-inspired: randomize to prevent session hijacking) */
    ctx->next_seq = (uint16_t)stealth_rand32();
    ctx->recv_seq = 0;
    ctx->ack_seq  = 0;

    /* Adaptive window defaults */
    ctx->window_size     = WINDOW_SIZE_DEFAULT;
    ctx->rtt_ewma_us     = 200000; /* initial estimate: 200ms */
    ctx->last_send_time_us = 0;

    /* Query type rotation defaults */
    ctx->query_type_idx   = 0;
    ctx->queries_on_type  = 0;
    ctx->rotate_interval  = 50; /* rotate every 50 queries */

    /* No crypto by default */
    crypto_init(&ctx->crypto, NULL, 0);

    return ERR_OK;
}

void transport_free(transport_ctx_t *ctx)
{
    if (!ctx) {
        return;
    }
    memset(ctx, 0, sizeof(*ctx));
}

/* ------------------------------------------------------------------ */
/* CRC over an entire packet (checksum field zeroed before compute)    */
/* ------------------------------------------------------------------ */

static uint16_t compute_packet_crc(const uint8_t *buf, size_t len)
{
    /* checksum occupies bytes 6-7 in the header (offset of tunnel_header_t.checksum) */
    uint8_t  tmp[TUNNEL_HEADER_SIZE + TUNNEL_MAX_PAYLOAD];
    uint16_t crc;

    if (len > sizeof(tmp)) {
        return 0;
    }

    memcpy(tmp, buf, len);
    /* Zero the checksum field (bytes 6 and 7) */
    tmp[6] = 0;
    tmp[7] = 0;

    crc = crc16_ccitt(tmp, len);
    return crc;
}

/* ------------------------------------------------------------------ */
/* Build a packet, store in ring buffer, return total length           */
/* ------------------------------------------------------------------ */

int transport_build_packet(transport_ctx_t *ctx, uint16_t session_id,
                           uint8_t flags,
                           const uint8_t *payload, size_t payload_len,
                           uint8_t *buf, size_t buf_cap)
{
    tunnel_header_t hdr;
    size_t          total;
    uint16_t        crc;
    size_t          slot_idx;
    ring_slot_t    *slot;

    if (!ctx || !buf) {
        return -1;
    }
    if (payload_len > TUNNEL_MAX_PAYLOAD) {
        return -1;
    }

    total = TUNNEL_HEADER_SIZE + payload_len;
    if (buf_cap < total) {
        return -1;
    }

    memset(&hdr, 0, sizeof(hdr));
    hdr.session_id  = session_id;
    hdr.seq_num     = ctx->next_seq;
    hdr.ack_num     = ctx->recv_seq;
    hdr.checksum    = 0;
    hdr.flags       = flags;
    hdr.payload_len = (uint8_t)payload_len;

    memcpy(buf, &hdr, TUNNEL_HEADER_SIZE);
    if (payload && payload_len > 0) {
        memcpy(buf + TUNNEL_HEADER_SIZE, payload, payload_len);
    }

    crc        = compute_packet_crc(buf, total);
    /* Store checksum big-endian at bytes 6-7 */
    buf[6] = (uint8_t)(crc >> 8);
    buf[7] = (uint8_t)(crc & 0xFFU);

    /* Store in ring buffer for potential retransmit */
    slot_idx = ctx->next_seq % RING_BUFFER_SIZE;
    slot     = &ctx->slots[slot_idx];

    memcpy(slot->data, buf, total);
    slot->len             = total;
    slot->seq             = ctx->next_seq;
    slot->in_use          = 1;
    slot->send_time_ms    = get_time_ms();
    slot->retransmit_count = 0;

    ctx->next_seq++;

    return (int)total;
}

/* ------------------------------------------------------------------ */
/* Parse & verify a received packet                                    */
/* ------------------------------------------------------------------ */

err_t transport_parse_packet(const uint8_t *buf, size_t len,
                             tunnel_header_t *hdr_out,
                             const uint8_t **payload_out,
                             size_t *payload_len_out)
{
    tunnel_header_t hdr;

    if (!buf || !hdr_out || !payload_out || !payload_len_out) {
        return ERR_INVAL;
    }
    if (len < TUNNEL_HEADER_SIZE) {
        return ERR_PROTO;
    }

    memcpy(&hdr, buf, TUNNEL_HEADER_SIZE);

    if (hdr.payload_len > TUNNEL_MAX_PAYLOAD) {
        return ERR_PROTO;
    }
    if (len < TUNNEL_HEADER_SIZE + (size_t)hdr.payload_len) {
        return ERR_PROTO;
    }

    /* Verify CRC to reject corrupted packets early */
    if (!transport_verify_checksum(buf, TUNNEL_HEADER_SIZE + (size_t)hdr.payload_len)) {
        return ERR_PROTO;
    }

    *hdr_out         = hdr;
    *payload_out     = buf + TUNNEL_HEADER_SIZE;
    *payload_len_out = hdr.payload_len;

    return ERR_OK;
}

int transport_verify_checksum(const uint8_t *buf, size_t len)
{
    tunnel_header_t hdr;
    uint16_t        expected;
    uint16_t        computed;

    if (!buf || len < TUNNEL_HEADER_SIZE) {
        return 0;
    }

    memcpy(&hdr, buf, TUNNEL_HEADER_SIZE);
    expected = (uint16_t)((buf[6] << 8) | buf[7]);
    computed = compute_packet_crc(buf, len);

    return (expected == computed) ? 1 : 0;
}

/* ------------------------------------------------------------------ */
/* Ring buffer                                                          */
/* ------------------------------------------------------------------ */

err_t transport_enqueue(transport_ctx_t *ctx,
                        const uint8_t *pkt, size_t pkt_len, uint16_t seq)
{
    size_t      slot_idx;
    ring_slot_t *slot;

    if (!ctx || !pkt) {
        return ERR_INVAL;
    }
    if (pkt_len > sizeof(slot->data)) {
        return ERR_OVERFLOW;
    }

    slot_idx = seq % RING_BUFFER_SIZE;
    slot     = &ctx->slots[slot_idx];

    memcpy(slot->data, pkt, pkt_len);
    slot->len             = pkt_len;
    slot->seq             = seq;
    slot->in_use          = 1;
    slot->send_time_ms    = get_time_ms();
    slot->retransmit_count = 0;

    return ERR_OK;
}

void transport_ack(transport_ctx_t *ctx, uint16_t ack_seq)
{
    size_t i;

    if (!ctx) {
        return;
    }

    /* Free all slots with seq <= ack_seq (accounting for wrap-around) */
    for (i = 0; i < RING_BUFFER_SIZE; i++) {
        ring_slot_t *slot = &ctx->slots[i];
        if (slot->in_use) {
            /* Sequence number comparison accounting for wraparound */
            uint16_t diff = (uint16_t)(ack_seq - slot->seq);
            if (diff < 0x8000U) {
                slot->in_use = 0;
            }
        }
    }

    ctx->ack_seq = ack_seq;
}

void transport_check_retransmit(
    transport_ctx_t *ctx, uint64_t now_ms, uint64_t timeout_ms,
    void (*retransmit_cb)(const uint8_t *pkt, size_t len, void *ud),
    void *userdata)
{
    size_t i;

    if (!ctx || !retransmit_cb) {
        return;
    }

    for (i = 0; i < RING_BUFFER_SIZE; i++) {
        ring_slot_t *slot = &ctx->slots[i];
        uint64_t     backoff;
        uint64_t     threshold;

        if (!slot->in_use) {
            continue;
        }

        /* Exponential backoff: timeout * 1.5^retransmit_count */
        backoff   = timeout_ms;
        {
            int n;
            for (n = 0; n < slot->retransmit_count; n++) {
                backoff = backoff + backoff / 2;
                if (backoff > 10000ULL) {
                    backoff = 10000ULL;
                    break;
                }
            }
        }
        threshold = slot->send_time_ms + backoff;

        if (now_ms >= threshold) {
            retransmit_cb(slot->data, slot->len, userdata);
            slot->send_time_ms     = now_ms;
            slot->retransmit_count++;
        }
    }
}

/* ------------------------------------------------------------------ */
/* PSK encryption setup                                                 */
/* ------------------------------------------------------------------ */

void transport_set_psk(transport_ctx_t *ctx,
                       const uint8_t *psk, size_t psk_len)
{
    if (!ctx) {
        return;
    }
    crypto_init(&ctx->crypto, psk, psk_len);
}

/* ------------------------------------------------------------------ */
/* Query type rotation (TODO #10, iodine-inspired)                      */
/* ------------------------------------------------------------------ */

int transport_next_query_type(transport_ctx_t *ctx)
{
    uint16_t qtype;

    if (!ctx) {
        return DNS_TYPE_TXT;
    }

    qtype = QUERY_TYPES[ctx->query_type_idx % NUM_QUERY_TYPES];
    ctx->queries_on_type++;

    if (ctx->queries_on_type >= ctx->rotate_interval) {
        ctx->query_type_idx = (ctx->query_type_idx + 1) % (int)NUM_QUERY_TYPES;
        ctx->queries_on_type = 0;
        /* Randomize the next rotation interval (30-120 queries) */
        ctx->rotate_interval = 30 + (int)(stealth_rand32() % 91U);
    }

    return (int)qtype;
}

/* ------------------------------------------------------------------ */
/* Adaptive window size (TODO #7, iodine-inspired)                      */
/* ------------------------------------------------------------------ */

void transport_update_rtt(transport_ctx_t *ctx, uint64_t rtt_us)
{
    uint64_t prev;

    if (!ctx || rtt_us == 0) {
        return;
    }

    prev = ctx->rtt_ewma_us;

    /* EWMA: rtt_ewma = 0.875 * rtt_ewma + 0.125 * sample */
    ctx->rtt_ewma_us = (prev * 7 + rtt_us) / 8;

    /* Adjust window based on RTT trend */
    if (ctx->rtt_ewma_us < prev && ctx->window_size < 32) {
        /* RTT improved → increase window */
        ctx->window_size++;
    } else if (ctx->rtt_ewma_us > prev + prev / 4 && ctx->window_size > 2) {
        /* RTT degraded significantly → decrease window */
        ctx->window_size--;
    }
    /* else: stable, no change */
}

/* ------------------------------------------------------------------ */
/* Session resume token (dnscat2-inspired)                              */
/* ------------------------------------------------------------------ */

void transport_generate_token(transport_ctx_t *ctx)
{
    if (!ctx) {
        return;
    }
    stealth_random_bytes(ctx->session_token, SESSION_TOKEN_SIZE);
    ctx->has_session_token = 1;
}
