#pragma once
#include "config.h"
#include "util.h"
#include "dns_packet.h"

typedef struct {
    int    basic_ok;
    int    a_ok;
    int    aaaa_ok;
    int    cname_ok;
    int    mx_ok;
    int    txt_ok;
    int    null_ok;
    int    naptr_ok;
    int    srv_ok;
    int    caa_ok;
    int    svcb_ok;
    int    soa_ok;
    int    edns0_ok;
    int    txid_preserved;
    int    edns_opt_preserved;
    int    auth_ns_preserved;
    int    addl_preserved;
    int    ttl_preserved;
    double avg_rtt_ms;
    double loss_pct;
    double est_bw_up_bps;
    double est_bw_down_bps;
    channel_caps_t caps;
} check_results_t;

err_t run_full_check(const client_config_t *cfg, check_results_t *results);
err_t run_connectivity_check(const client_config_t *cfg);
err_t run_benchmark(const client_config_t *cfg, int duration_secs);
