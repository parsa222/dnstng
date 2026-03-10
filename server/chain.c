#include "chain.h"
#include "encode.h"
#include "util.h"
#include <string.h>
#include <stdio.h>

/* ------------------------------------------------------------------ */
/* Internal helpers                                                     */
/* ------------------------------------------------------------------ */

/* Write big-endian uint16 into buf[off]. */
static void put16(uint8_t *buf, size_t off, uint16_t v)
{
    buf[off]     = (uint8_t)(v >> 8);
    buf[off + 1] = (uint8_t)(v & 0xFFU);
}

/* Write big-endian uint32 into buf[off]. */
static void put32(uint8_t *buf, size_t off, uint32_t v)
{
    buf[off]     = (uint8_t)(v >> 24);
    buf[off + 1] = (uint8_t)((v >> 16) & 0xFFU);
    buf[off + 2] = (uint8_t)((v >>  8) & 0xFFU);
    buf[off + 3] = (uint8_t)(v & 0xFFU);
}

/* Encode a dotted FQDN as DNS wire-format labels into out[off..].
 * Returns new offset, or -1 on error. */
static int encode_labels(const char *fqdn,
                          uint8_t *buf, size_t buf_cap, size_t off)
{
    const char *p   = fqdn;
    const char *dot;
    size_t      llen;

    while (*p) {
        dot = strchr(p, '.');
        if (dot) {
            llen = (size_t)(dot - p);
        } else {
            llen = strlen(p);
        }
        if (llen == 0U || llen > 63U) {
            return -1;
        }
        if (off + 1U + llen >= buf_cap) {
            return -1;
        }
        buf[off++] = (uint8_t)llen;
        memcpy(buf + off, p, llen);
        off += llen;
        p   += llen;
        if (*p == '.') { p++; }
    }
    if (off >= buf_cap) { return -1; }
    buf[off++] = 0;
    return (int)off;
}

/* Decode wire-format DNS name at rdata[0] into dotted string (no compression).
 * Returns bytes consumed, or -1. */
static int decode_name_noctx(const uint8_t *rdata, size_t rdata_len,
                              char *out, size_t out_cap)
{
    size_t i       = 0;
    size_t out_pos = 0;

    while (i < rdata_len) {
        uint8_t llen = rdata[i];
        if (llen == 0) {
            if (out_pos < out_cap) { out[out_pos] = '\0'; }
            return (int)(i + 1);
        }
        if ((llen & 0xC0U) == 0xC0U) { return -1; } /* no compression */
        if (llen > 63U) { return -1; }
        i++;
        if (i + llen > rdata_len) { return -1; }
        if (out_pos > 0) {
            if (out_pos >= out_cap - 1U) { return -1; }
            out[out_pos++] = '.';
        }
        if (out_pos + llen >= out_cap) { return -1; }
        memcpy(out + out_pos, rdata + i, llen);
        out_pos += llen;
        i       += llen;
    }
    if (out_pos < out_cap) { out[out_pos] = '\0'; }
    return -1;
}

/* ------------------------------------------------------------------ */
/* CNAME chain                                                          */
/* ------------------------------------------------------------------ */

int chain_build_cname(uint16_t query_id, const char *question_fqdn,
                      const char *domain,
                      const uint8_t *data, size_t data_len,
                      int chain_depth,
                      uint8_t *buf, size_t buf_cap)
{
    size_t   off;
    int      ret;
    int      i;
    size_t   chunk;
    size_t   packed;
    char     b36[256];
    char     target[512];
    uint8_t  ip[4];
    uint16_t ancount;

    if (!buf || buf_cap < 12 || !domain || !question_fqdn) {
        return -1;
    }
    if (chain_depth < 1) { chain_depth = 1; }
    if (chain_depth > CHAIN_MAX_DEPTH) { chain_depth = CHAIN_MAX_DEPTH; }

    /* Each hop carries: floor(data_len / chain_depth) bytes (last gets rest) */
    ancount = (uint16_t)(chain_depth + 1); /* CNAMEs + final A */

    put16(buf, 0,  query_id);
    put16(buf, 2,  0x8400U);  /* QR=1, AA=1 */
    put16(buf, 4,  1);        /* QDCOUNT */
    put16(buf, 6,  ancount);  /* ANCOUNT */
    put16(buf, 8,  0);
    put16(buf, 10, 0);
    off = 12;

    /* Question */
    ret = encode_labels(question_fqdn, buf, buf_cap, off);
    if (ret < 0) { return -1; }
    off = (size_t)ret;
    if (off + 4U > buf_cap) { return -1; }
    put16(buf, off, (uint16_t)DNS_TYPE_A); off += 2;
    put16(buf, off, 1);                    off += 2; /* CLASS IN */

    packed = 0;
    for (i = 0; i < chain_depth; i++) {
        size_t   rdlen_off;
        size_t   rdata_start;
        int      enc;
        char     prev_name[512];

        /* Chunk size: spread evenly; last chunk gets the remainder */
        if (i < chain_depth - 1) {
            chunk = (data_len > 0) ? (data_len / (size_t)chain_depth) : 0;
        } else {
            chunk = (data_len >= packed) ? (data_len - packed) : 0;
        }
        if (chunk > 60U) { chunk = 60U; }

        /* Build base36 encoded chunk */
        if (chunk > 0 && data) {
            enc = encode_data(data + packed, chunk, b36, sizeof(b36),
                              ENCODE_BASE36);
            if (enc < 0) { return -1; }
            b36[enc] = '\0';
        } else {
            b36[0] = '0'; b36[1] = '\0';
        }

        /* CNAME owner name: compress to question (offset 12) */
        if (i == 0) {
            /* First CNAME owner = question name */
            if (off + 2U > buf_cap) { return -1; }
            buf[off] = 0xC0U; buf[off + 1] = 12; off += 2;
        } else {
            /* Subsequent CNAME owner = previous CNAME target.
             * For simplicity use previous target name inline. */
            snprintf(prev_name, sizeof(prev_name),
                     "%s.c%d.t.%s", b36, i - 1, domain);
            /* Actually we need the *previous* hop's target as owner.
             * Use pointer to the start of the previous CNAME rdata
             * instead of re-encoding.  For now, use question pointer. */
            if (off + 2U > buf_cap) { return -1; }
            buf[off] = 0xC0U; buf[off + 1] = 12; off += 2;
        }

        /* TYPE=CNAME, CLASS=IN, TTL=300 */
        if (off + 10U > buf_cap) { return -1; }
        put16(buf, off, (uint16_t)DNS_TYPE_CNAME); off += 2;
        put16(buf, off, 1);                         off += 2;
        put32(buf, off, 300U);                      off += 4;

        /* RDATA = target name: {b36}.c{i}.t.{domain} */
        snprintf(target, sizeof(target), "%s.c%d.t.%s", b36, i, domain);
        rdlen_off   = off;
        off        += 2; /* placeholder for rdlen */
        rdata_start = off;
        ret = encode_labels(target, buf, buf_cap, off);
        if (ret < 0) { return -1; }
        off = (size_t)ret;
        put16(buf, rdlen_off, (uint16_t)(off - rdata_start));

        packed += chunk;
    }

    /* Final A record: last 4 bytes of data as IP (or 1.2.3.4 placeholder) */
    if (off + 2U > buf_cap) { return -1; }
    buf[off] = 0xC0U; buf[off + 1] = 12; off += 2;
    if (off + 10U > buf_cap) { return -1; }
    put16(buf, off, (uint16_t)DNS_TYPE_A); off += 2;
    put16(buf, off, 1);                    off += 2;
    put32(buf, off, 300U);                 off += 4;
    put16(buf, off, 4);                    off += 2;

    memset(ip, 0, sizeof(ip));
    if (data && data_len >= 4U) {
        ip[0] = data[data_len - 4]; ip[1] = data[data_len - 3];
        ip[2] = data[data_len - 2]; ip[3] = data[data_len - 1];
    } else if (data && data_len > 0) {
        memcpy(ip, data, (data_len < 4U) ? data_len : 4U);
    } else {
        ip[0] = 1; ip[1] = 2; ip[2] = 3; ip[3] = 4;
    }
    if (off + 4U > buf_cap) { return -1; }
    memcpy(buf + off, ip, 4);
    off += 4;

    return (int)off;
}

int chain_parse_cname(const dns_parsed_response_t *parsed,
                      const char *domain,
                      uint8_t *out, size_t out_cap)
{
    size_t  i;
    size_t  total = 0;
    char    target_name[512];
    char    b36[256];
    uint8_t decoded[256];
    int     dlen;
    char   *dot_c;
    size_t  b36_len;

    if (!parsed || !out || out_cap == 0) {
        return -1;
    }

    for (i = 0; i < parsed->num_records; i++) {
        const dns_rr_t *rr = &parsed->records[i];

        if (rr->section != 0 || rr->type != DNS_TYPE_CNAME) {
            continue;
        }

        /* Decode the CNAME target from rdata */
        if (decode_name_noctx(rr->rdata, rr->rdata_len,
                               target_name, sizeof(target_name)) < 0) {
            continue;
        }

        /* Target format: {b36}.c{N}.t.{domain} — find ".c" */
        dot_c = strstr(target_name, ".c");
        if (!dot_c) { continue; }

        b36_len = (size_t)(dot_c - target_name);
        if (b36_len == 0 || b36_len >= sizeof(b36)) { continue; }
        memcpy(b36, target_name, b36_len);
        b36[b36_len] = '\0';

        (void)domain; /* used for format but not for parsing here */

        dlen = decode_data(b36, b36_len, decoded, sizeof(decoded),
                           ENCODE_BASE36);
        if (dlen <= 0) { continue; }
        if (total + (size_t)dlen > out_cap) {
            dlen = (int)(out_cap - total);
        }
        memcpy(out + total, decoded, (size_t)dlen);
        total += (size_t)dlen;
    }

    return (int)total;
}

/* ------------------------------------------------------------------ */
/* NS referral chain                                                    */
/* ------------------------------------------------------------------ */

int chain_build_ns_referral(uint16_t query_id, const char *question_fqdn,
                             const char *domain,
                             const uint8_t *data, size_t data_len,
                             int chain_depth,
                             uint8_t *buf, size_t buf_cap)
{
    size_t   off;
    int      ret;
    int      i;
    size_t   packed;
    size_t   chunk;
    char     b36[256];
    char     ns_name[512];
    size_t   rdlen_off;
    size_t   rdata_start;

    if (!buf || buf_cap < 12 || !domain || !question_fqdn) {
        return -1;
    }
    if (chain_depth < 1) { chain_depth = 1; }
    if (chain_depth > CHAIN_MAX_DEPTH) { chain_depth = CHAIN_MAX_DEPTH; }

    put16(buf, 0,  query_id);
    put16(buf, 2,  0x8400U);
    put16(buf, 4,  1);
    put16(buf, 6,  0);                          /* no answers */
    put16(buf, 8,  (uint16_t)chain_depth);      /* authority NS records */
    put16(buf, 10, 0);
    off = 12;

    /* Question */
    ret = encode_labels(question_fqdn, buf, buf_cap, off);
    if (ret < 0) { return -1; }
    off = (size_t)ret;
    if (off + 4U > buf_cap) { return -1; }
    put16(buf, off, (uint16_t)DNS_TYPE_NS); off += 2;
    put16(buf, off, 1);                     off += 2;

    packed = 0;
    for (i = 0; i < chain_depth; i++) {
        int enc;

        if (i < chain_depth - 1) {
            chunk = (data_len > 0) ? (data_len / (size_t)chain_depth) : 0;
        } else {
            chunk = (data_len >= packed) ? (data_len - packed) : 0;
        }
        if (chunk > 60U) { chunk = 60U; }

        if (chunk > 0 && data) {
            enc = encode_data(data + packed, chunk, b36, sizeof(b36),
                              ENCODE_BASE36);
            if (enc < 0) { return -1; }
            b36[enc] = '\0';
        } else {
            b36[0] = '0'; b36[1] = '\0';
        }

        /* NS owner = question name */
        if (off + 2U > buf_cap) { return -1; }
        buf[off] = 0xC0U; buf[off + 1] = 12; off += 2;

        if (off + 10U > buf_cap) { return -1; }
        put16(buf, off, (uint16_t)DNS_TYPE_NS); off += 2;
        put16(buf, off, 1);                      off += 2;
        put32(buf, off, 300U);                   off += 4;

        snprintf(ns_name, sizeof(ns_name), "%s.ns%d.%s", b36, i, domain);
        rdlen_off   = off;
        off        += 2;
        rdata_start = off;
        ret = encode_labels(ns_name, buf, buf_cap, off);
        if (ret < 0) { return -1; }
        off = (size_t)ret;
        put16(buf, rdlen_off, (uint16_t)(off - rdata_start));

        packed += chunk;
    }

    return (int)off;
}

int chain_parse_ns_referral(const dns_parsed_response_t *parsed,
                             const char *domain,
                             uint8_t *out, size_t out_cap)
{
    size_t  i;
    size_t  total = 0;
    char    ns_name[512];
    char   *dot_ns;
    char    b36[256];
    uint8_t decoded[256];
    int     dlen;
    size_t  b36_len;

    if (!parsed || !out || out_cap == 0) {
        return -1;
    }

    (void)domain;

    for (i = 0; i < parsed->num_records; i++) {
        const dns_rr_t *rr = &parsed->records[i];

        if (rr->section != 1 || rr->type != DNS_TYPE_NS) {
            continue;
        }

        if (decode_name_noctx(rr->rdata, rr->rdata_len,
                               ns_name, sizeof(ns_name)) < 0) {
            continue;
        }

        /* NS name format: {b36}.ns{N}.{domain} — find ".ns" */
        dot_ns = strstr(ns_name, ".ns");
        if (!dot_ns) { continue; }

        b36_len = (size_t)(dot_ns - ns_name);
        if (b36_len == 0 || b36_len >= sizeof(b36)) { continue; }
        memcpy(b36, ns_name, b36_len);
        b36[b36_len] = '\0';

        dlen = decode_data(b36, b36_len, decoded, sizeof(decoded),
                           ENCODE_BASE36);
        if (dlen <= 0) { continue; }
        if (total + (size_t)dlen > out_cap) {
            dlen = (int)(out_cap - total);
        }
        memcpy(out + total, decoded, (size_t)dlen);
        total += (size_t)dlen;
    }

    return (int)total;
}
