#pragma once
#include <stdint.h>
#include <stddef.h>
#include <sys/socket.h>
#include <uv.h>
#include "util.h"
#include "dns_packet.h"

typedef void (*dns_query_cb_t)(uint16_t query_id,
                               const char *fqdn, dns_type_t qtype,
                               const struct sockaddr *from, socklen_t from_len,
                               void *userdata);

typedef struct {
    uv_udp_t       udp;
    uv_loop_t     *loop;
    char           domain[256];
    dns_query_cb_t on_query;
    void          *userdata;
} dns_server_t;

err_t dns_server_init(dns_server_t *srv, uv_loop_t *loop,
                      const char *bind_addr, uint16_t port,
                      const char *domain);
err_t dns_server_start(dns_server_t *srv);
void  dns_server_stop(dns_server_t *srv);
err_t dns_server_respond(dns_server_t *srv, uint16_t query_id,
                          const char *fqdn, dns_type_t qtype,
                          const struct sockaddr *to, socklen_t to_len,
                          const uint8_t *data, size_t data_len);
