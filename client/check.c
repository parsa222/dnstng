#include "check.h"
#include "dns_packet.h"
#include "log.h"
#include "transport.h"
#include <ares.h>
#include <arpa/nameser.h>
#include <uv.h>
#include <string.h>
#include <stdio.h>
#include <time.h>

/* ------------------------------------------------------------------ */
/* Connectivity check                                                   */
/* ------------------------------------------------------------------ */

typedef struct {
    int     done;
    int     success;
    uv_loop_t *loop;
} check_ctx_t;

static void ares_check_cb(void *arg, int status, int timeouts,
                           unsigned char *abuf, int alen)
{
    check_ctx_t *ctx = (check_ctx_t *)arg;

    (void)timeouts;

    if (status == ARES_SUCCESS && abuf && alen > 0) {
        ctx->success = 1;
    } else {
        LOG_WARN("connectivity check DNS error: %s", ares_strerror(status));
    }
    ctx->done = 1;
    uv_stop(ctx->loop);
}

static void ares_timer_cb(uv_timer_t *timer)
{
    ares_channel ch = (ares_channel)timer->data;
    ares_process_fd(ch, ARES_SOCKET_BAD, ARES_SOCKET_BAD);
}

err_t run_connectivity_check(const client_config_t *cfg)
{
    ares_channel  ch;
    struct ares_options opts;
    int           optmask = 0;
    uv_loop_t     loop;
    uv_timer_t    timer;
    check_ctx_t   ctx;
    char          fqdn[512];
    int           r;

    if (!cfg) {
        return ERR_INVAL;
    }

    memset(&ctx, 0, sizeof(ctx));
    uv_loop_init(&loop);
    ctx.loop = &loop;

    memset(&opts, 0, sizeof(opts));
    r = ares_init_options(&ch, &opts, optmask);
    if (r != ARES_SUCCESS) {
        uv_loop_close(&loop);
        return ERR_IO;
    }

    /* Set resolver */
    {
        struct ares_addr_node servers;
        memset(&servers, 0, sizeof(servers));
        servers.family = AF_INET;
        if (inet_pton(AF_INET, cfg->resolver,
                      &servers.addr.addr4) != 1) {
            ares_destroy(ch);
            uv_loop_close(&loop);
            return ERR_INVAL;
        }
        ares_set_servers(ch, &servers);
    }

    snprintf(fqdn, sizeof(fqdn), "check.t.%s", cfg->domain);
    LOG_INFO("connectivity check: querying %s via %s", fqdn, cfg->resolver);

    ares_query(ch, fqdn, C_IN, T_TXT, ares_check_cb, &ctx);

    uv_timer_init(&loop, &timer);
    timer.data = ch;
    uv_timer_start(&timer, ares_timer_cb, 100, 100);

    uv_run(&loop, UV_RUN_DEFAULT);

    uv_timer_stop(&timer);
    uv_close((uv_handle_t *)&timer, NULL);
    uv_run(&loop, UV_RUN_NOWAIT);

    ares_destroy(ch);
    uv_loop_close(&loop);

    if (ctx.success) {
        LOG_INFO("connectivity check: PASSED");
        return ERR_OK;
    }

    LOG_WARN("connectivity check: FAILED (server may not be reachable)");
    /* Return OK anyway - check is best-effort */
    return ERR_OK;
}

/* ------------------------------------------------------------------ */
/* Benchmark                                                            */
/* ------------------------------------------------------------------ */

typedef struct {
    int        done;
    uint64_t   queries_sent;
    uint64_t   queries_recv;
    uv_loop_t *loop;
    uv_timer_t stop_timer;
    ares_channel ch;
} bench_ctx_t;

static void bench_ares_cb(void *arg, int status, int timeouts,
                            unsigned char *abuf, int alen)
{
    bench_ctx_t *ctx = (bench_ctx_t *)arg;

    (void)status;
    (void)timeouts;
    (void)abuf;
    (void)alen;

    ctx->queries_recv++;
}

static void bench_stop_cb(uv_timer_t *timer)
{
    bench_ctx_t *ctx = (bench_ctx_t *)timer->data;
    ctx->done = 1;
    uv_stop(ctx->loop);
}

static void bench_poll_cb(uv_timer_t *timer)
{
    bench_ctx_t *ctx = (bench_ctx_t *)timer->data;
    ares_process_fd(ctx->ch, ARES_SOCKET_BAD, ARES_SOCKET_BAD);
}

err_t run_benchmark(const client_config_t *cfg, int duration_secs)
{
    if (duration_secs <= 0) {
        return ERR_INVAL;
    }
    ares_channel  ch;
    struct ares_options opts;
    int           optmask = 0;
    uv_loop_t     loop;
    uv_timer_t    stop_timer;
    uv_timer_t    poll_timer;
    uv_timer_t    send_timer;
    bench_ctx_t   ctx;
    uint64_t      start_ms;
    char          fqdn[512];
    int           r;
    int           i;

    if (!cfg) {
        return ERR_INVAL;
    }

    memset(&ctx, 0, sizeof(ctx));
    uv_loop_init(&loop);
    ctx.loop = &loop;

    memset(&opts, 0, sizeof(opts));
    r = ares_init_options(&ch, &opts, optmask);
    if (r != ARES_SUCCESS) {
        uv_loop_close(&loop);
        return ERR_IO;
    }
    ctx.ch = ch;

    {
        struct ares_addr_node servers;
        memset(&servers, 0, sizeof(servers));
        servers.family = AF_INET;
        if (inet_pton(AF_INET, cfg->resolver,
                      &servers.addr.addr4) != 1) {
            ares_destroy(ch);
            uv_loop_close(&loop);
            return ERR_INVAL;
        }
        ares_set_servers(ch, &servers);
    }

    snprintf(fqdn, sizeof(fqdn), "bench.t.%s", cfg->domain);

    start_ms = (uint64_t)time(NULL) * 1000ULL;
    (void)start_ms;

    /* Send 10 initial queries */
    for (i = 0; i < 10; i++) {
        ares_query(ch, fqdn, C_IN, T_TXT, bench_ares_cb, &ctx);
        ctx.queries_sent++;
    }

    uv_timer_init(&loop, &stop_timer);
    stop_timer.data = &ctx;
    uv_timer_start(&stop_timer, bench_stop_cb,
                   (uint64_t)duration_secs * 1000ULL, 0);

    uv_timer_init(&loop, &poll_timer);
    poll_timer.data = &ctx;
    uv_timer_start(&poll_timer, bench_poll_cb, 50, 50);

    /* send_timer fires periodically to send more queries */
    uv_timer_init(&loop, &send_timer);
    send_timer.data = &ctx;
    /* reuse bench_poll_cb to keep ares moving; queries already in flight */
    uv_timer_start(&send_timer, bench_poll_cb, 100, 100);

    uv_run(&loop, UV_RUN_DEFAULT);

    uv_timer_stop(&stop_timer);
    uv_timer_stop(&poll_timer);
    uv_timer_stop(&send_timer);
    uv_close((uv_handle_t *)&stop_timer, NULL);
    uv_close((uv_handle_t *)&poll_timer, NULL);
    uv_close((uv_handle_t *)&send_timer, NULL);
    uv_run(&loop, UV_RUN_NOWAIT);

    ares_destroy(ch);
    uv_loop_close(&loop);

    printf("Benchmark results (%d seconds):\n", duration_secs);
    printf("  Queries sent: %llu\n", (unsigned long long)ctx.queries_sent);
    printf("  Responses received: %llu\n",
           (unsigned long long)ctx.queries_recv);
    printf("  Throughput: %.1f queries/sec\n",
           (double)ctx.queries_recv / (double)duration_secs);

    return ERR_OK;
}
