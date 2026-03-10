#pragma once
#include <stdint.h>
#include <stddef.h>
#include <uv.h>
#include "util.h"

/*
 * SMTP backup tunnel.
 * Uses TCP to tunnel data over SMTP protocol.
 * Upstream data is encoded in EHLO hostname labels.
 * Downstream data comes in 250-continuation lines.
 */

typedef struct smtp_channel_s smtp_channel_t;

typedef void (*smtp_recv_cb_t)(const uint8_t *data, size_t len, void *userdata);
/* 1=connected, 0=disconnected */
typedef void (*smtp_conn_cb_t)(int connected, void *userdata);

struct smtp_channel_s {
    uv_loop_t     *loop;
    uv_tcp_t       tcp;
    uv_connect_t   connect_req;
    char           host[256];
    uint16_t       port;
    char           domain[256];   /* tunnel domain for encoding */
    smtp_recv_cb_t on_recv;
    smtp_conn_cb_t on_conn;
    void          *userdata;
    int            connected;
    uint8_t        recv_buf[4096];
    size_t         recv_len;
    uint8_t        send_buf[4096];
    size_t         send_len;
    uv_write_t     write_req;
};

err_t smtp_channel_init(smtp_channel_t *ch, uv_loop_t *loop,
                        const char *host, uint16_t port,
                        const char *domain);
err_t smtp_channel_connect(smtp_channel_t *ch);
err_t smtp_channel_send(smtp_channel_t *ch,
                        const uint8_t *data, size_t len);
void  smtp_channel_free(smtp_channel_t *ch);
