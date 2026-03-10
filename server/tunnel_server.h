#pragma once
#include <stdint.h>
#include <stddef.h>
#include <sys/socket.h>
#include <uv.h>
#include "transport.h"
#include "config.h"
#include "dns_server.h"

#define MAX_SESSIONS 1024

typedef enum {
    SERVER_SESSION_NEW = 0,
    SERVER_SESSION_ACTIVE,
    SERVER_SESSION_CLOSING,
} server_session_state_t;

typedef struct {
    uint16_t               session_id;
    server_session_state_t state;
    transport_ctx_t        transport;
    uint64_t               last_activity_ms;
    struct sockaddr_storage client_addr;
    socklen_t               client_addr_len;
} server_session_t;

typedef struct {
    uv_loop_t        *loop;
    dns_server_t      dns;
    server_config_t   cfg;
    server_session_t  sessions[MAX_SESSIONS];
    uv_timer_t        cleanup_timer;
} tunnel_server_t;

err_t tunnel_server_init(tunnel_server_t *ts, uv_loop_t *loop,
                          const server_config_t *cfg);
err_t tunnel_server_start(tunnel_server_t *ts);
void  tunnel_server_stop(tunnel_server_t *ts);
void  tunnel_server_free(tunnel_server_t *ts);
