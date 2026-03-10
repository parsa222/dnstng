#pragma once
#include <stddef.h>
#include "util.h"

#define CONFIG_MAX_STR 256

/* Forward declarations */
typedef struct client_config_s client_config_t;
typedef struct server_config_s server_config_t;

#include "encode.h"
#include "log.h"
#include "dns_packet.h"

struct client_config_s {
    char          domain[CONFIG_MAX_STR];
    char          resolver[64];
    char          listen_addr[64];
    uint16_t      listen_port;
    log_level_t   log_level;
    encode_mode_t encode_mode;
    uint32_t      active_channels;   /* bitmask of CHAN_* */
    int           cname_chain_depth; /* 0=disabled, 1-8 */
    int           ns_chain_depth;    /* 0=disabled, 1-4 */
    int           ttl_encoding;      /* 0=disabled, 1=stealth, 2=full */
    char          smtp_host[64];     /* backup SMTP host */
    uint16_t      smtp_port;         /* backup SMTP port (default 25) */
    char          ocsp_host[64];     /* backup OCSP host */
    uint16_t      ocsp_port;         /* backup OCSP port (default 80) */
    char          crl_host[64];      /* backup CRL host */
    uint16_t      crl_port;          /* backup CRL port (default 80) */
};

struct server_config_s {
    char        domain[CONFIG_MAX_STR];
    char        bind_addr[64];
    uint16_t    bind_port;
    char        upstream_dns[64];
    log_level_t log_level;
    uint32_t    active_channels;    /* bitmask of CHAN_* */
    int         cname_chain_depth;
    int         ns_chain_depth;
    int         ttl_encoding;
};

void  config_client_defaults(client_config_t *cfg);
void  config_server_defaults(server_config_t *cfg);
err_t config_load_client(const char *path, client_config_t *cfg);
err_t config_load_server(const char *path, server_config_t *cfg);
