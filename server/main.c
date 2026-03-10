#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <uv.h>
#include "config.h"
#include "log.h"
#include "tunnel_server.h"
#include "util.h"

static void print_usage(const char *prog)
{
    fprintf(stdout,
            "Usage: %s [options]\n"
            "  --config <file>        Load configuration file\n"
            "  --domain <domain>      Tunnel domain\n"
            "  --listen <addr:port>   DNS listen address (default 0.0.0.0:53)\n"
            "  --upstream <ip>        Upstream DNS resolver\n"
            "  --loglevel <level>     Log level: debug|info|warn|error\n"
            "  --help                 Show this message\n",
            prog);
}

static log_level_t parse_loglevel(const char *s)
{
    if (strcmp(s, "debug") == 0) { return LOG_DEBUG; }
    if (strcmp(s, "warn")  == 0) { return LOG_WARN;  }
    if (strcmp(s, "error") == 0) { return LOG_ERROR; }
    return LOG_INFO;
}

static int parse_addr_port(const char *addrport, char *addr, size_t addr_cap,
                             uint16_t *port)
{
    const char *colon;
    size_t      addr_len;

    colon = strrchr(addrport, ':');
    if (!colon) {
        return -1;
    }

    addr_len = (size_t)(colon - addrport);
    if (addr_len == 0 || addr_len >= addr_cap) {
        return -1;
    }

    memcpy(addr, addrport, addr_len);
    addr[addr_len] = '\0';
    *port = (uint16_t)atoi(colon + 1);
    return 0;
}

int main(int argc, char *argv[])
{
    server_config_t  cfg;
    int              i;
    uv_loop_t        loop;
    tunnel_server_t  ts;
    err_t            e;

    config_server_defaults(&cfg);

    for (i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--help") == 0) {
            print_usage(argv[0]);
            return 0;
        } else if (strcmp(argv[i], "--config") == 0 && i + 1 < argc) {
            i++;
            config_load_server(argv[i], &cfg);
        } else if (strcmp(argv[i], "--domain") == 0 && i + 1 < argc) {
            i++;
            strncpy(cfg.domain, argv[i], sizeof(cfg.domain) - 1);
        } else if (strcmp(argv[i], "--listen") == 0 && i + 1 < argc) {
            i++;
            parse_addr_port(argv[i], cfg.bind_addr,
                             sizeof(cfg.bind_addr), &cfg.bind_port);
        } else if (strcmp(argv[i], "--upstream") == 0 && i + 1 < argc) {
            i++;
            strncpy(cfg.upstream_dns, argv[i], sizeof(cfg.upstream_dns) - 1);
        } else if (strcmp(argv[i], "--loglevel") == 0 && i + 1 < argc) {
            i++;
            cfg.log_level = parse_loglevel(argv[i]);
        } else {
            fprintf(stderr, "Unknown option: %s\n", argv[i]);
            print_usage(argv[0]);
            return 1;
        }
    }

    log_set_level(cfg.log_level);

    uv_loop_init(&loop);

    e = tunnel_server_init(&ts, &loop, &cfg);
    if (e != ERR_OK) {
        LOG_ERROR("Failed to init tunnel server: %s", err_str(e));
        uv_loop_close(&loop);
        return 1;
    }

    e = tunnel_server_start(&ts);
    if (e != ERR_OK) {
        LOG_ERROR("Failed to start tunnel server: %s", err_str(e));
        tunnel_server_free(&ts);
        uv_loop_close(&loop);
        return 1;
    }

    LOG_INFO("DNS tunnel server started");
    LOG_INFO("  Domain:   %s", cfg.domain);
    LOG_INFO("  Listen:   %s:%u", cfg.bind_addr, cfg.bind_port);
    LOG_INFO("  Upstream: %s", cfg.upstream_dns);

    uv_run(&loop, UV_RUN_DEFAULT);

    tunnel_server_stop(&ts);
    tunnel_server_free(&ts);
    uv_loop_close(&loop);

    return 0;
}
