#pragma once
#include <stdint.h>
#include <stddef.h>
#include "util.h"

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

typedef struct {
    uint8_t  data[TUNNEL_HEADER_SIZE + TUNNEL_MAX_PAYLOAD];
    size_t   len;
    uint16_t seq;
    int      in_use;
    uint64_t send_time_ms;
    int      retransmit_count;
} ring_slot_t;

typedef struct {
    ring_slot_t slots[RING_BUFFER_SIZE];
    uint16_t    next_seq;
    uint16_t    ack_seq;
    uint16_t    recv_seq;
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
