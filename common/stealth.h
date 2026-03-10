#pragma once
#include <stdint.h>
#include <stddef.h>

void     stealth_random_bytes(uint8_t *buf, size_t len);
uint32_t stealth_rand32(void);
uint64_t stealth_jitter(uint64_t delay_ms);
double   stealth_entropy(const uint8_t *data, size_t len);

#define NOISE_DOMAIN_COUNT 100
extern const char *const NOISE_DOMAINS[NOISE_DOMAIN_COUNT];
