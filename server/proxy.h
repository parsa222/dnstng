#pragma once
#include <stdint.h>
#include <stddef.h>
#include <uv.h>
#include "util.h"

typedef void (*proxy_data_cb_t)(uint16_t stream_id,
                                const uint8_t *data, size_t len,
                                void *userdata);
typedef void (*proxy_close_cb_t)(uint16_t stream_id, void *userdata);

typedef struct proxy_conn_s {
    uv_tcp_t         tcp;
    uv_connect_t     connect_req;
    uint16_t         stream_id;
    proxy_data_cb_t  on_data;
    proxy_close_cb_t on_close;
    void            *userdata;
    struct proxy_conn_s *next;
} proxy_conn_t;

typedef struct {
    uv_loop_t       *loop;
    proxy_conn_t    *connections;
    proxy_data_cb_t  on_data;
    proxy_close_cb_t on_close;
    void            *userdata;
} proxy_t;

err_t proxy_init(proxy_t *proxy, uv_loop_t *loop);
err_t proxy_connect(proxy_t *proxy, uint16_t stream_id,
                    const char *host, uint16_t port);
err_t proxy_send(proxy_t *proxy, uint16_t stream_id,
                 const uint8_t *data, size_t len);
void  proxy_close(proxy_t *proxy, uint16_t stream_id);
void  proxy_free(proxy_t *proxy);
