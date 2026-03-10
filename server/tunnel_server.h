#pragma once
#include <stdint.h>
#include <stddef.h>
#include <sys/socket.h>
#include <uv.h>
#include "transport.h"
#include "config.h"
#include "dns_server.h"

#define MAX_SESSIONS 1024

/* Lazy mode: max pending (unanswered) DNS queries per session.
 * iodine-inspired: the server delays answering queries until data
 * arrives, so there's always a query ready for immediate response. */
#define LAZY_QUEUE_SIZE 4

typedef enum {
    SERVER_SESSION_NEW = 0,
    SERVER_SESSION_ACTIVE,
    SERVER_SESSION_CLOSING,
} server_session_state_t;

/* A pending DNS query that we haven't responded to yet (lazy mode) */
typedef struct {
    uint16_t                query_id;
    char                    question_fqdn[256];
    uint16_t                query_type;
    struct sockaddr_storage client_addr;
    socklen_t               client_addr_len;
    uint64_t                received_ms;
    int                     valid;
} pending_query_t;

typedef struct {
    uint16_t               session_id;
    server_session_state_t state;
    transport_ctx_t        transport;
    uint64_t               last_activity_ms;
    struct sockaddr_storage client_addr;
    socklen_t               client_addr_len;
    /* Lazy mode: pending unanswered queries */
    pending_query_t        pending[LAZY_QUEUE_SIZE];
    int                    pending_count;
    /* Downstream data buffer (data waiting to be sent to client) */
    uint8_t                downstream_buf[2048];
    size_t                 downstream_len;
} server_session_t;

typedef struct {
    uv_loop_t        *loop;
    dns_server_t      dns;
    server_config_t   cfg;
    server_session_t  sessions[MAX_SESSIONS];
    uv_timer_t        cleanup_timer;
    uv_timer_t        lazy_timer;   /* Timer to drain lazy queues */
} tunnel_server_t;

err_t tunnel_server_init(tunnel_server_t *ts, uv_loop_t *loop,
                          const server_config_t *cfg);
err_t tunnel_server_start(tunnel_server_t *ts);
void  tunnel_server_stop(tunnel_server_t *ts);
void  tunnel_server_free(tunnel_server_t *ts);
