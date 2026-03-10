#pragma once
#include <stdint.h>
#include <stddef.h>
#include <uv.h>
#include <ares.h>
#include "transport.h"
#include "config.h"
#include "socks5.h"

#define MAX_STREAMS      256
#define MAX_RETRIES      5

/* Adaptive poll interval bounds (iodine-inspired).
 * Starts at POLL_MIN_MS, ramps up to POLL_MAX_MS when idle,
 * drops back to POLL_MIN_MS when data is flowing. */
#define POLL_MIN_MS      100
#define POLL_MAX_MS      4000
#define POLL_RAMP_STEP   50   /* ms added per idle poll */

typedef enum {
    SESSION_INIT = 0,
    SESSION_HANDSHAKE,
    SESSION_ACTIVE,
    SESSION_CLOSING,
} session_state_t;

struct socks5_conn_s; /* forward */

typedef struct {
    uint16_t      stream_id;
    int           active;
    uint8_t       send_buf[4096];
    size_t        send_len;
    uint8_t       recv_buf[4096];
    size_t        recv_len;
    socks5_conn_t *socks5;
} stream_t;

typedef struct tunnel_client_s {
    uv_loop_t       *loop;
    ares_channel     ares;
    transport_ctx_t  transport;
    client_config_t  cfg;
    session_state_t  state;
    uint16_t         session_id;
    stream_t         streams[MAX_STREAMS];
    uv_timer_t       poll_timer;
    uv_timer_t       retransmit_timer;
    int              ares_fd;
    /* Adaptive poll interval (TODO #8, iodine-inspired) */
    uint64_t         poll_interval_ms;   /* current poll interval */
    uint64_t         last_data_recv_ms;  /* last time data was received */
    int              idle_polls;         /* consecutive polls with no data */
} tunnel_client_t;

err_t tunnel_client_init(tunnel_client_t *tc, uv_loop_t *loop,
                          const client_config_t *cfg);
err_t tunnel_client_start(tunnel_client_t *tc);
void  tunnel_client_stop(tunnel_client_t *tc);
err_t tunnel_client_send(tunnel_client_t *tc, uint16_t stream_id,
                          const uint8_t *data, size_t len);
void  tunnel_client_free(tunnel_client_t *tc);
void  tunnel_client_setup_socks5(tunnel_client_t *tc, socks5_server_t *srv);
