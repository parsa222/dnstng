#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <uv.h>
#include "config.h"
#include "log.h"
#include "tunnel_client.h"
#include "socks5.h"
#include "check.h"

static void print_usage(const char *prog)
{
    fprintf(stdout,
            "Usage: %s [options]\n"
            "  --config <file>        Load configuration file\n"
            "  --domain <domain>      Tunnel domain\n"
            "  --resolver <ip>        DNS resolver IP\n"
            "  --listen <addr:port>   SOCKS5 listen address (default 127.0.0.1:1080)\n"
            "  --check                Run connectivity check and exit\n"
            "  --benchmark            Run benchmark\n"
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
    client_config_t  cfg;
    int              do_check     = 0;
    int              do_benchmark = 0;
    int              i;
    uv_loop_t        loop;
    tunnel_client_t  tc;
    socks5_server_t  socks5srv;
    err_t            e;

    config_client_defaults(&cfg);

    for (i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--help") == 0) {
            print_usage(argv[0]);
            return 0;
        } else if (strcmp(argv[i], "--config") == 0 && i + 1 < argc) {
            i++;
            config_load_client(argv[i], &cfg);
        } else if (strcmp(argv[i], "--domain") == 0 && i + 1 < argc) {
            i++;
            strncpy(cfg.domain, argv[i], sizeof(cfg.domain) - 1);
        } else if (strcmp(argv[i], "--resolver") == 0 && i + 1 < argc) {
            i++;
            strncpy(cfg.resolver, argv[i], sizeof(cfg.resolver) - 1);
        } else if (strcmp(argv[i], "--listen") == 0 && i + 1 < argc) {
            i++;
            parse_addr_port(argv[i], cfg.listen_addr,
                             sizeof(cfg.listen_addr), &cfg.listen_port);
        } else if (strcmp(argv[i], "--check") == 0) {
            do_check = 1;
        } else if (strcmp(argv[i], "--benchmark") == 0) {
            do_benchmark = 1;
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

    if (do_check) {
        return run_connectivity_check(&cfg) == ERR_OK ? 0 : 1;
    }

    if (do_benchmark) {
        return run_benchmark(&cfg, 10) == ERR_OK ? 0 : 1;
    }

    uv_loop_init(&loop);

    e = tunnel_client_init(&tc, &loop, &cfg);
    if (e != ERR_OK) {
        LOG_ERROR("Failed to init tunnel client: %s", err_str(e));
        uv_loop_close(&loop);
        return 1;
    }

    e = socks5_server_init(&socks5srv, &loop,
                            cfg.listen_addr, cfg.listen_port);
    if (e != ERR_OK) {
        LOG_ERROR("Failed to init SOCKS5 server: %s", err_str(e));
        tunnel_client_free(&tc);
        uv_loop_close(&loop);
        return 1;
    }

    tunnel_client_setup_socks5(&tc, &socks5srv);

    e = socks5_server_start(&socks5srv);
    if (e != ERR_OK) {
        LOG_ERROR("Failed to start SOCKS5 server: %s", err_str(e));
        tunnel_client_free(&tc);
        uv_loop_close(&loop);
        return 1;
    }

    e = tunnel_client_start(&tc);
    if (e != ERR_OK) {
        LOG_ERROR("Failed to start tunnel client: %s", err_str(e));
        socks5_server_stop(&socks5srv);
        tunnel_client_free(&tc);
        uv_loop_close(&loop);
        return 1;
    }

    LOG_INFO("DNS tunnel client started");
    LOG_INFO("  Domain:   %s", cfg.domain);
    LOG_INFO("  Resolver: %s", cfg.resolver);
    LOG_INFO("  SOCKS5:   %s:%u", cfg.listen_addr, cfg.listen_port);

    uv_run(&loop, UV_RUN_DEFAULT);

    tunnel_client_stop(&tc);
    tunnel_client_free(&tc);
    uv_loop_close(&loop);

    return 0;
}
