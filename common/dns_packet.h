#pragma once
#include <stdint.h>
#include <stddef.h>
#include "util.h"

typedef enum {
    DNS_TYPE_A     = 1,
    DNS_TYPE_NS    = 2,
    DNS_TYPE_CNAME = 5,
    DNS_TYPE_SOA   = 6,
    DNS_TYPE_NULL_ = 10,
    DNS_TYPE_MX    = 15,
    DNS_TYPE_TXT   = 16,
    DNS_TYPE_AAAA  = 28,
    DNS_TYPE_SRV   = 33,
    DNS_TYPE_NAPTR = 35,
    DNS_TYPE_SVCB  = 64,
    DNS_TYPE_HTTPS = 65,
    DNS_TYPE_CAA   = 257,
} dns_type_t;

/* EDNS0 custom option code for tunnel data */
#define EDNS0_TUNNEL_OPTION 65001U

/* Multi-channel capabilities bit flags */
#define CHAN_TXID         0x01U  /* TXID carries upstream data */
#define CHAN_EDNS_OPT     0x02U  /* EDNS0 custom option carries upstream data */
#define CHAN_AUTH_NS      0x04U  /* Authority NS names carry downstream data */
#define CHAN_ADDL_GLUE    0x08U  /* Additional glue records carry downstream data */
#define CHAN_TTL_DATA     0x10U  /* TTL fields carry downstream data */
#define CHAN_MULTI_ANSWER 0x20U  /* Multiple answer records */

/* Channel probe result */
typedef struct {
    uint32_t active_channels;   /* bitmask of CHAN_* */
    int      txid_preserved;
    int      edns_opt_preserved;
    int      auth_ns_preserved;
    int      addl_preserved;
    int      ttl_preserved;
} channel_caps_t;

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

/* ------------------------------------------------------------------ */
/* Original API                                                         */
/* ------------------------------------------------------------------ */

int   dns_build_query(uint16_t id, const char *fqdn, dns_type_t qtype,
                      int use_edns0, uint16_t edns0_size,
                      uint8_t *buf, size_t buf_cap);
err_t dns_parse_response(const uint8_t *buf, size_t len,
                         dns_answer_cb_t cb, void *userdata);
int   dns_build_response(uint16_t id, const char *question_fqdn,
                         dns_type_t qtype,
                         const dns_answer_t *answers, size_t num_answers,
                         uint8_t *buf, size_t buf_cap);

/* ------------------------------------------------------------------ */
/* Extended query — includes custom EDNS0 option                        */
/* ------------------------------------------------------------------ */

int dns_build_query_ext(uint16_t id,
                        const char *fqdn, dns_type_t qtype,
                        int use_edns0, uint16_t edns0_size,
                        const uint8_t *edns_opt_data, size_t edns_opt_len,
                        uint8_t *buf, size_t buf_cap);

/* ------------------------------------------------------------------ */
/* Extended response — Authority + Additional + EDNS0 option            */
/* ------------------------------------------------------------------ */

typedef struct {
    /* Answer section */
    const dns_answer_t *answers;
    size_t              num_answers;
    /* Authority section: NS records */
    const char        **auth_ns_names;  /* e.g. "ns1.tunnel.example.com" */
    size_t              num_auth_ns;
    uint32_t            auth_ns_ttl;
    /* Additional section: A/AAAA glue */
    const dns_answer_t *addl_records;
    size_t              num_addl;
    /* EDNS0 OPT option in response */
    const uint8_t      *edns_opt_data;
    size_t              edns_opt_len;
    uint16_t            edns0_size;     /* 0 = no EDNS0 in response */
} dns_response_ext_t;

int dns_build_response_ext(uint16_t id,
                           const char *question_fqdn, dns_type_t qtype,
                           const dns_response_ext_t *resp,
                           uint8_t *buf, size_t buf_cap);

/* ------------------------------------------------------------------ */
/* Full response parser — all sections + EDNS0 options                  */
/* ------------------------------------------------------------------ */

typedef struct {
    dns_type_t type;
    uint8_t    rdata[1024];
    size_t     rdata_len;
    uint32_t   ttl;
    uint8_t    section;  /* 0=answer, 1=authority, 2=additional */
    char       name[256];
} dns_rr_t;

typedef struct {
    dns_rr_t    records[128];
    size_t      num_records;
    uint8_t     edns_opt[512];
    size_t      edns_opt_len;
    uint16_t    txid;
    uint16_t    question_type;
} dns_parsed_response_t;

err_t dns_parse_response_full(const uint8_t *buf, size_t len,
                               dns_parsed_response_t *out);

/* ------------------------------------------------------------------ */
/* RDATA builders for individual record types                           */
/* ------------------------------------------------------------------ */

int dns_build_naptr_rdata(uint16_t order, uint16_t pref,
                          const char *flags, const char *service,
                          const char *regexp, const char *replacement,
                          uint8_t *out, size_t out_cap);

int dns_build_srv_rdata(uint16_t prio, uint16_t weight, uint16_t port,
                        const char *target,
                        uint8_t *out, size_t out_cap);

int dns_build_caa_rdata(uint8_t flags, const char *tag, const char *value,
                        uint8_t *out, size_t out_cap);

int dns_build_soa_rdata(const char *mname, const char *rname,
                        uint32_t serial, uint32_t refresh,
                        uint32_t retry, uint32_t expire,
                        uint32_t minimum,
                        uint8_t *out, size_t out_cap);
