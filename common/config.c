#include "config.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>

static void trim(char *s)
{
    char  *start = s;
    char  *end;
    size_t len;

    /* Find first non-whitespace */
    while (*start && isspace((unsigned char)*start)) {
        start++;
    }

    len = strlen(start);
    if (start != s) {
        memmove(s, start, len + 1);
    }

    if (len == 0) {
        return;
    }

    /* Trailing whitespace */
    end = s + len - 1;
    while (end > s && isspace((unsigned char)*end)) {
        *end-- = '\0';
    }
}

void config_client_defaults(client_config_t *cfg)
{
    memset(cfg, 0, sizeof(*cfg));
    strncpy(cfg->domain,      "tunnel.example.com", sizeof(cfg->domain) - 1);
    strncpy(cfg->resolver,    "8.8.8.8",            sizeof(cfg->resolver) - 1);
    strncpy(cfg->listen_addr, "127.0.0.1",          sizeof(cfg->listen_addr) - 1);
    cfg->listen_port  = 1080;
    cfg->log_level    = LOG_INFO;
    cfg->encode_mode  = ENCODE_BASE32;
}

void config_server_defaults(server_config_t *cfg)
{
    memset(cfg, 0, sizeof(*cfg));
    strncpy(cfg->domain,       "tunnel.example.com", sizeof(cfg->domain) - 1);
    strncpy(cfg->bind_addr,    "0.0.0.0",            sizeof(cfg->bind_addr) - 1);
    strncpy(cfg->upstream_dns, "8.8.8.8",            sizeof(cfg->upstream_dns) - 1);
    cfg->bind_port  = 53;
    cfg->log_level  = LOG_INFO;
}

/* Generic key=value parser.  Calls set_kv for each pair found.
 * Returns ERR_OK or ERR_IO. */
typedef void (*kv_cb_t)(const char *key, const char *val, void *ud);

static err_t parse_config_file(const char *path, kv_cb_t cb, void *ud)
{
    FILE  *f;
    char   line[512];

    f = fopen(path, "r");
    if (!f) {
        return ERR_IO;
    }

    while (fgets(line, (int)sizeof(line), f)) {
        char *eq;
        char  key[256];
        char  val[256];

        /* Strip newline */
        line[strcspn(line, "\r\n")] = '\0';

        /* Skip comments and empty lines */
        if (line[0] == '#' || line[0] == '\0') {
            continue;
        }

        eq = strchr(line, '=');
        if (!eq) {
            continue;
        }

        *eq = '\0';
        strncpy(key, line, sizeof(key) - 1);
        key[sizeof(key) - 1] = '\0';
        strncpy(val, eq + 1, sizeof(val) - 1);
        val[sizeof(val) - 1] = '\0';

        trim(key);
        trim(val);

        if (key[0] != '\0') {
            cb(key, val, ud);
        }
    }

    fclose(f);
    return ERR_OK;
}

static void client_kv(const char *key, const char *val, void *ud)
{
    client_config_t *cfg = (client_config_t *)ud;

    if (strcmp(key, "domain") == 0) {
        strncpy(cfg->domain, val, sizeof(cfg->domain) - 1);
    } else if (strcmp(key, "resolver") == 0) {
        strncpy(cfg->resolver, val, sizeof(cfg->resolver) - 1);
    } else if (strcmp(key, "listen_addr") == 0) {
        strncpy(cfg->listen_addr, val, sizeof(cfg->listen_addr) - 1);
    } else if (strcmp(key, "listen_port") == 0) {
        cfg->listen_port = (uint16_t)atoi(val);
    } else if (strcmp(key, "log_level") == 0) {
        if (strcmp(val, "debug") == 0) {
            cfg->log_level = LOG_DEBUG;
        } else if (strcmp(val, "warn") == 0) {
            cfg->log_level = LOG_WARN;
        } else if (strcmp(val, "error") == 0) {
            cfg->log_level = LOG_ERROR;
        } else {
            cfg->log_level = LOG_INFO;
        }
    } else if (strcmp(key, "encode_mode") == 0) {
        cfg->encode_mode = (strcmp(val, "base32") == 0)
                               ? ENCODE_BASE32
                               : ENCODE_BASE36;
    }
}

static void server_kv(const char *key, const char *val, void *ud)
{
    server_config_t *cfg = (server_config_t *)ud;

    if (strcmp(key, "domain") == 0) {
        strncpy(cfg->domain, val, sizeof(cfg->domain) - 1);
    } else if (strcmp(key, "bind_addr") == 0) {
        strncpy(cfg->bind_addr, val, sizeof(cfg->bind_addr) - 1);
    } else if (strcmp(key, "bind_port") == 0) {
        cfg->bind_port = (uint16_t)atoi(val);
    } else if (strcmp(key, "upstream_dns") == 0) {
        strncpy(cfg->upstream_dns, val, sizeof(cfg->upstream_dns) - 1);
    } else if (strcmp(key, "log_level") == 0) {
        if (strcmp(val, "debug") == 0) {
            cfg->log_level = LOG_DEBUG;
        } else if (strcmp(val, "warn") == 0) {
            cfg->log_level = LOG_WARN;
        } else if (strcmp(val, "error") == 0) {
            cfg->log_level = LOG_ERROR;
        } else {
            cfg->log_level = LOG_INFO;
        }
    }
}

err_t config_load_client(const char *path, client_config_t *cfg)
{
    if (!path || !cfg) {
        return ERR_INVAL;
    }
    return parse_config_file(path, client_kv, cfg);
}

err_t config_load_server(const char *path, server_config_t *cfg)
{
    if (!path || !cfg) {
        return ERR_INVAL;
    }
    return parse_config_file(path, server_kv, cfg);
}
