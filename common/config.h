#pragma once
#include <stddef.h>
#include "util.h"

#define CONFIG_MAX_STR 256

/* Forward declarations */
typedef struct client_config_s client_config_t;
typedef struct server_config_s server_config_t;

#include "encode.h"
#include "log.h"

struct client_config_s {
    char          domain[CONFIG_MAX_STR];
    char          resolver[64];
    char          listen_addr[64];
    uint16_t      listen_port;
    log_level_t   log_level;
    encode_mode_t encode_mode;
};

struct server_config_s {
    char        domain[CONFIG_MAX_STR];
    char        bind_addr[64];
    uint16_t    bind_port;
    char        upstream_dns[64];
    log_level_t log_level;
};

void  config_client_defaults(client_config_t *cfg);
void  config_server_defaults(server_config_t *cfg);
err_t config_load_client(const char *path, client_config_t *cfg);
err_t config_load_server(const char *path, server_config_t *cfg);
