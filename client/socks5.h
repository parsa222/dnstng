#pragma once
#include <stdint.h>
#include <stddef.h>
#include <uv.h>
#include "util.h"

typedef enum {
    S5_STATE_GREETING = 0,
    S5_STATE_REQUEST,
    S5_STATE_CONNECTED,
} socks5_state_t;

struct socks5_conn_s;

typedef void (*socks5_connect_cb)(struct socks5_conn_s *conn,
                                  const char *host, uint16_t port,
                                  void *userdata);
typedef void (*socks5_data_cb)(struct socks5_conn_s *conn,
                               const uint8_t *data, size_t len,
                               void *userdata);
typedef void (*socks5_close_cb)(struct socks5_conn_s *conn, void *userdata);

#define SOCKS5_BUF_SIZE 8192

typedef struct socks5_conn_s {
    uv_tcp_t         tcp;
    socks5_state_t   state;
    uint8_t          buf[SOCKS5_BUF_SIZE];
    size_t           buf_len;
    socks5_connect_cb on_connect;
    socks5_data_cb    on_data;
    socks5_close_cb   on_close;
    void             *userdata;
    char              target_host[256];
    uint16_t          target_port;
    int               closed;
} socks5_conn_t;

typedef struct {
    uv_tcp_t          server;
    uv_loop_t        *loop;
    socks5_connect_cb on_connect;
    socks5_data_cb    on_data;
    socks5_close_cb   on_close;
    void             *userdata;
} socks5_server_t;

err_t socks5_server_init(socks5_server_t *srv, uv_loop_t *loop,
                          const char *bind_addr, uint16_t port);
err_t socks5_server_start(socks5_server_t *srv);
void  socks5_server_stop(socks5_server_t *srv);
err_t socks5_conn_send(socks5_conn_t *conn,
                       const uint8_t *data, size_t len);
void  socks5_conn_close(socks5_conn_t *conn);
