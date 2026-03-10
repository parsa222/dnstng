#pragma once
#include <stdint.h>
#include <stddef.h>
#include "util.h"

typedef enum {
    DNS_TYPE_A     = 1,
    DNS_TYPE_CNAME = 5,
    DNS_TYPE_MX    = 15,
    DNS_TYPE_TXT   = 16,
    DNS_TYPE_AAAA  = 28,
    DNS_TYPE_NULL_ = 10,
} dns_type_t;

typedef struct {
    uint16_t id;
    uint16_t flags;
} dns_header_t;

typedef struct {
    dns_type_t      type;
    const uint8_t  *rdata;
    size_t          rdata_len;
    uint32_t        ttl;
} dns_answer_t;

typedef void (*dns_answer_cb_t)(dns_type_t type,
                                const uint8_t *rdata, size_t rdata_len,
                                void *userdata);

int   dns_build_query(uint16_t id, const char *fqdn, dns_type_t qtype,
                      int use_edns0, uint16_t edns0_size,
                      uint8_t *buf, size_t buf_cap);
err_t dns_parse_response(const uint8_t *buf, size_t len,
                         dns_answer_cb_t cb, void *userdata);
int   dns_build_response(uint16_t id, const char *question_fqdn,
                         dns_type_t qtype,
                         const dns_answer_t *answers, size_t num_answers,
                         uint8_t *buf, size_t buf_cap);
