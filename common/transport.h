#pragma once
#include <stdint.h>
#include <stddef.h>
#include "util.h"
#include "crypto.h"

/* --- packet flags --- */
#define TUNNEL_FLAG_SYN  0x01
#define TUNNEL_FLAG_ACK  0x02
#define TUNNEL_FLAG_FIN  0x04
#define TUNNEL_FLAG_DATA 0x08
#define TUNNEL_FLAG_POLL 0x10

/* Suppress pedantic warning for __attribute__((packed)) */
#ifdef __GNUC__
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wpedantic"
#endif

typedef struct {
    uint16_t session_id;
    uint16_t seq_num;
    uint16_t ack_num;
    uint16_t checksum;
    uint8_t  flags;
    uint8_t  payload_len;
} __attribute__((packed)) tunnel_header_t;

#ifdef __GNUC__
#pragma GCC diagnostic pop
#endif

#define TUNNEL_HEADER_SIZE  sizeof(tunnel_header_t)
#define TUNNEL_MAX_PAYLOAD  200
#define RING_BUFFER_SIZE    64
#define WINDOW_SIZE_DEFAULT 8

/* Session resume token size (dnscat2-inspired) */
#define SESSION_TOKEN_SIZE  8

typedef struct {
    uint8_t  data[TUNNEL_HEADER_SIZE + TUNNEL_MAX_PAYLOAD];
    size_t   len;
    uint16_t seq;
    int      in_use;
    uint64_t send_time_ms;
    int      retransmit_count;
} ring_slot_t;

typedef struct {
    ring_slot_t  slots[RING_BUFFER_SIZE];
    uint16_t     next_seq;
    uint16_t     ack_seq;
    uint16_t     recv_seq;
    uint32_t     active_channels;   /* bitmask of CHAN_* from dns_packet.h */
    crypto_ctx_t crypto;            /* PSK encryption context */
    uint8_t      session_token[SESSION_TOKEN_SIZE]; /* for session resume */
    int          has_session_token;  /* 1 if token is set */
    /* Adaptive window size (iodine-inspired) */
    int          window_size;       /* current window (2..32) */
    uint64_t     rtt_ewma_us;      /* EWMA of RTT in microseconds */
    uint64_t     last_send_time_us; /* timestamp of last send */
    /* Query type rotation (TODO #10) */
    int          query_type_idx;    /* current index in rotation list */
    int          queries_on_type;   /* queries sent with current type */
    int          rotate_interval;   /* queries before rotation (30-120) */
} transport_ctx_t;

err_t    transport_init(transport_ctx_t *ctx);
void     transport_free(transport_ctx_t *ctx);
int      transport_build_packet(transport_ctx_t *ctx, uint16_t session_id,
                                uint8_t flags,
                                const uint8_t *payload, size_t payload_len,
                                uint8_t *buf, size_t buf_cap);
err_t    transport_parse_packet(const uint8_t *buf, size_t len,
                                tunnel_header_t *hdr_out,
                                const uint8_t **payload_out,
                                size_t *payload_len_out);
int      transport_verify_checksum(const uint8_t *buf, size_t len);
err_t    transport_enqueue(transport_ctx_t *ctx,
                           const uint8_t *pkt, size_t pkt_len, uint16_t seq);
void     transport_check_retransmit(
             transport_ctx_t *ctx, uint64_t now_ms, uint64_t timeout_ms,
             void (*retransmit_cb)(const uint8_t *pkt, size_t len, void *ud),
             void *userdata);
void     transport_ack(transport_ctx_t *ctx, uint16_t ack_seq);
uint64_t get_time_ms(void);

/* Initialize transport with encryption (PSK). If psk is NULL, no encryption. */
void     transport_set_psk(transport_ctx_t *ctx,
                           const uint8_t *psk, size_t psk_len);

/* Get the DNS query type for the next query (rotates among types) */
int      transport_next_query_type(transport_ctx_t *ctx);

/* Update RTT measurement and adaptive window */
void     transport_update_rtt(transport_ctx_t *ctx, uint64_t rtt_us);

/* Generate / set session resume token */
void     transport_generate_token(transport_ctx_t *ctx);
