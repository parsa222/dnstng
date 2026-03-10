#pragma once
#include "config.h"
#include "util.h"

err_t run_connectivity_check(const client_config_t *cfg);
err_t run_benchmark(const client_config_t *cfg, int duration_secs);
