#pragma once
#include <stdint.h>
#include <stddef.h>
#include "dns_packet.h"
#include "util.h"

#define CHAIN_MAX_DEPTH 8

/* Build a CNAME chain response.
 * data[0..data_len-1] is split across chain_depth CNAME records.
 * Each CNAME target is: {base36_chunk}.c{i}.t.{domain}
 * The final answer is an A record with the last 4 bytes (or 0.0.0.0).
 * Returns the number of bytes written to buf, or -1 on error. */
int chain_build_cname(uint16_t query_id, const char *question_fqdn,
                      const char *domain,
                      const uint8_t *data, size_t data_len,
                      int chain_depth,
                      uint8_t *buf, size_t buf_cap);

/* Parse a CNAME chain from a parsed response.
 * Extracts data from CNAME target labels across all chain hops.
 * Returns total bytes extracted, or -1 on error. */
int chain_parse_cname(const dns_parsed_response_t *parsed,
                      const char *domain,
                      uint8_t *out, size_t out_cap);

/* Build an NS referral chain response.
 * Responds with NS records in authority section pointing to sub-nameservers,
 * with data encoded in NS names.
 * Returns bytes written, or -1 on error. */
int chain_build_ns_referral(uint16_t query_id, const char *question_fqdn,
                             const char *domain,
                             const uint8_t *data, size_t data_len,
                             int chain_depth,
                             uint8_t *buf, size_t buf_cap);

/* Parse NS referral chain from parsed response.
 * Returns total bytes extracted, or -1. */
int chain_parse_ns_referral(const dns_parsed_response_t *parsed,
                             const char *domain,
                             uint8_t *out, size_t out_cap);
