#include "dns_packet.h"
#include <string.h>
#include <stdlib.h>

/* ------------------------------------------------------------------ */
/* Internal helpers                                                     */
/* ------------------------------------------------------------------ */

/* Encode a dotted FQDN into DNS wire-format labels.
 * Writes into buf[off..].  Returns new offset or -1 on error. */
static int encode_labels(const char *fqdn, uint8_t *buf, size_t buf_cap,
                          size_t off)
{
    const char *p    = fqdn;
    const char *dot;
    size_t      label_len;

    while (*p) {
        dot = strchr(p, '.');
        if (dot) {
            label_len = (size_t)(dot - p);
        } else {
            label_len = strlen(p);
        }

        if (label_len == 0 || label_len > 63) {
            return -1;
        }
        if (off + 1 + label_len >= buf_cap) {
            return -1;
        }

        buf[off++] = (uint8_t)label_len;
        memcpy(buf + off, p, label_len);
        off += label_len;

        p += label_len;
        if (*p == '.') {
            p++;
        }
    }

    if (off >= buf_cap) {
        return -1;
    }
    buf[off++] = 0; /* root label */
    return (int)off;
}

/* Decode DNS wire-format labels at buf[off] into a dotted string.
 * Handles compression pointers.
 * Returns the offset after the label sequence (not after a pointer target),
 * or -1 on error.  out is NUL-terminated. */
static int decode_labels(const uint8_t *buf, size_t buf_len, size_t off,
                          char *out, size_t out_cap)
{
    size_t  out_pos   = 0;
    int     followed  = 0;  /* have we followed a pointer? */
    int     end_off   = -1; /* offset after the first pointer */
    size_t  cur       = off;
    int     loops     = 0;

    while (cur < buf_len && loops++ < 128) {
        uint8_t c = buf[cur];

        if (c == 0) {
            /* End of name */
            if (!followed) {
                end_off = (int)(cur + 1);
            }
            break;
        }

        if ((c & 0xC0U) == 0xC0U) {
            /* Compression pointer */
            size_t target;
            if (cur + 1 >= buf_len) {
                return -1;
            }
            target = (size_t)(((c & 0x3FU) << 8) | buf[cur + 1]);
            if (!followed) {
                end_off = (int)(cur + 2);
            }
            followed = 1;
            cur      = target;
            continue;
        }

        /* Ordinary label */
        {
            uint8_t label_len = c;
            cur++;

            if (cur + label_len > buf_len) {
                return -1;
            }
            if (out_pos > 0) {
                if (out_pos >= out_cap - 1) {
                    return -1;
                }
                out[out_pos++] = '.';
            }
            if (out_pos + label_len >= out_cap) {
                return -1;
            }
            memcpy(out + out_pos, buf + cur, label_len);
            out_pos += label_len;
            cur     += label_len;
        }
    }

    if (out_pos < out_cap) {
        out[out_pos] = '\0';
    } else {
        return -1;
    }

    return end_off;
}

/* Write a 16-bit big-endian value */
static void put_u16(uint8_t *buf, size_t off, uint16_t v)
{
    buf[off]     = (uint8_t)(v >> 8);
    buf[off + 1] = (uint8_t)(v & 0xFFU);
}

/* Read a 16-bit big-endian value */
static uint16_t get_u16(const uint8_t *buf, size_t off)
{
    return (uint16_t)((buf[off] << 8) | buf[off + 1]);
}

/* Write a 32-bit big-endian value */
static void put_u32(uint8_t *buf, size_t off, uint32_t v)
{
    buf[off]     = (uint8_t)(v >> 24);
    buf[off + 1] = (uint8_t)((v >> 16) & 0xFFU);
    buf[off + 2] = (uint8_t)((v >>  8) & 0xFFU);
    buf[off + 3] = (uint8_t)(v & 0xFFU);
}

static uint32_t get_u32(const uint8_t *buf, size_t off)
{
    return ((uint32_t)buf[off]     << 24)
         | ((uint32_t)buf[off + 1] << 16)
         | ((uint32_t)buf[off + 2] <<  8)
         |  (uint32_t)buf[off + 3];
}

/* ------------------------------------------------------------------ */
/* dns_build_query                                                      */
/* ------------------------------------------------------------------ */

int dns_build_query(uint16_t id, const char *fqdn, dns_type_t qtype,
                    int use_edns0, uint16_t edns0_size,
                    uint8_t *buf, size_t buf_cap)
{
    size_t off = 0;
    int    ret;

    if (!fqdn || !buf || buf_cap < 12) {
        return -1;
    }

    /* Header */
    put_u16(buf, 0, id);
    put_u16(buf, 2, 0x0100U); /* QR=0, RD=1 */
    put_u16(buf, 4, 1);       /* QDCOUNT=1 */
    put_u16(buf, 6, 0);       /* ANCOUNT=0 */
    put_u16(buf, 8, 0);       /* NSCOUNT=0 */
    put_u16(buf, 10, use_edns0 ? 1 : 0); /* ARCOUNT */
    off = 12;

    /* Question */
    ret = encode_labels(fqdn, buf, buf_cap, off);
    if (ret < 0) {
        return -1;
    }
    off = (size_t)ret;

    if (off + 4 > buf_cap) {
        return -1;
    }
    put_u16(buf, off, (uint16_t)qtype);
    put_u16(buf, off + 2, 1); /* CLASS=IN */
    off += 4;

    /* EDNS0 OPT pseudo-record */
    if (use_edns0) {
        if (off + 11 > buf_cap) {
            return -1;
        }
        buf[off++] = 0;              /* NAME = root */
        put_u16(buf, off, 41);       /* TYPE = OPT */
        off += 2;
        put_u16(buf, off, edns0_size ? edns0_size : 4096);
        off += 2;                    /* CLASS = requestor payload size */
        put_u32(buf, off, 0);        /* TTL = extended RCODE + flags = 0 */
        off += 4;
        put_u16(buf, off, 0);        /* RDLENGTH = 0 */
        off += 2;
    }

    return (int)off;
}

/* ------------------------------------------------------------------ */
/* dns_parse_response                                                   */
/* ------------------------------------------------------------------ */

err_t dns_parse_response(const uint8_t *buf, size_t len,
                          dns_answer_cb_t cb, void *userdata)
{
    uint16_t qdcount;
    uint16_t ancount;
    size_t   off = 0;
    uint16_t i;
    char     name_tmp[512];
    int      ret;

    if (!buf || len < 12) {
        return ERR_PROTO;
    }

    qdcount = get_u16(buf, 4);
    ancount = get_u16(buf, 6);
    off     = 12;

    /* Skip questions */
    for (i = 0; i < qdcount; i++) {
        ret = decode_labels(buf, len, off, name_tmp, sizeof(name_tmp));
        if (ret < 0) {
            return ERR_PROTO;
        }
        off = (size_t)ret;
        if (off + 4 > len) {
            return ERR_PROTO;
        }
        off += 4; /* QTYPE + QCLASS */
    }

    /* Parse answers */
    for (i = 0; i < ancount; i++) {
        uint16_t rtype;
        uint32_t ttl;
        uint16_t rdlen;

        ret = decode_labels(buf, len, off, name_tmp, sizeof(name_tmp));
        if (ret < 0) {
            return ERR_PROTO;
        }
        off = (size_t)ret;

        if (off + 10 > len) {
            return ERR_PROTO;
        }

        rtype = get_u16(buf, off);     off += 2;
        off  += 2;                     /* CLASS */
        ttl   = get_u32(buf, off);     off += 4;
        rdlen = get_u16(buf, off);     off += 2;

        (void)ttl; /* not used in callback */

        if (off + rdlen > len) {
            return ERR_PROTO;
        }

        if (cb) {
            cb((dns_type_t)rtype, buf + off, rdlen, userdata);
        }

        off += rdlen;
    }

    return ERR_OK;
}

/* ------------------------------------------------------------------ */
/* dns_build_response                                                   */
/* ------------------------------------------------------------------ */

int dns_build_response(uint16_t id, const char *question_fqdn,
                        dns_type_t qtype,
                        const dns_answer_t *answers, size_t num_answers,
                        uint8_t *buf, size_t buf_cap)
{
    size_t  off = 0;
    size_t  i;
    int     ret;

    if (!buf || buf_cap < 12) {
        return -1;
    }

    /* Header */
    put_u16(buf, 0, id);
    put_u16(buf, 2, 0x8400U); /* QR=1, AA=1 */
    put_u16(buf, 4, 1);       /* QDCOUNT=1 */
    put_u16(buf, 6, (uint16_t)num_answers);
    put_u16(buf, 8, 0);
    put_u16(buf, 10, 0);
    off = 12;

    /* Echo question */
    if (question_fqdn) {
        ret = encode_labels(question_fqdn, buf, buf_cap, off);
        if (ret < 0) {
            return -1;
        }
        off = (size_t)ret;
    } else {
        if (off >= buf_cap) {
            return -1;
        }
        buf[off++] = 0;
    }

    if (off + 4 > buf_cap) {
        return -1;
    }
    put_u16(buf, off, (uint16_t)qtype);
    put_u16(buf, off + 2, 1);
    off += 4;

    /* Answers */
    for (i = 0; i < num_answers; i++) {
        const dns_answer_t *ans = &answers[i];
        size_t              rdlen;

        if (off + 2 > buf_cap) {
            return -1;
        }
        /* NAME: pointer to question name (offset 12) */
        buf[off]     = 0xC0U;
        buf[off + 1] = 12;
        off += 2;

        if (off + 10 > buf_cap) {
            return -1;
        }
        put_u16(buf, off, (uint16_t)ans->type); off += 2;
        put_u16(buf, off, 1);                   off += 2; /* CLASS=IN */
        put_u32(buf, off, ans->ttl);             off += 4;

        rdlen = ans->rdata_len;

        /* For TXT records, RDATA is: 1 byte length + data */
        if (ans->type == DNS_TYPE_TXT) {
            if (off + 2 + 1 + rdlen > buf_cap) {
                return -1;
            }
            put_u16(buf, off, (uint16_t)(1 + rdlen)); off += 2;
            buf[off++] = (uint8_t)rdlen;
            memcpy(buf + off, ans->rdata, rdlen);
            off += rdlen;
        } else {
            /* NULL and others: raw RDATA */
            if (off + 2 + rdlen > buf_cap) {
                return -1;
            }
            put_u16(buf, off, (uint16_t)rdlen); off += 2;
            if (rdlen > 0) {
                memcpy(buf + off, ans->rdata, rdlen);
                off += rdlen;
            }
        }
    }

    return (int)off;
}

/* ------------------------------------------------------------------ */
/* dns_build_query_ext                                                  */
/* ------------------------------------------------------------------ */

int dns_build_query_ext(uint16_t id,
                        const char *fqdn, dns_type_t qtype,
                        int use_edns0, uint16_t edns0_size,
                        const uint8_t *edns_opt_data, size_t edns_opt_len,
                        uint8_t *buf, size_t buf_cap)
{
    size_t off     = 0;
    int    ret;
    int    has_edns = use_edns0 || (edns_opt_data != NULL && edns_opt_len > 0);

    if (!fqdn || !buf || buf_cap < 12) {
        return -1;
    }

    put_u16(buf, 0,  id);
    put_u16(buf, 2,  0x0100U);
    put_u16(buf, 4,  1);
    put_u16(buf, 6,  0);
    put_u16(buf, 8,  0);
    put_u16(buf, 10, has_edns ? 1 : 0);
    off = 12;

    ret = encode_labels(fqdn, buf, buf_cap, off);
    if (ret < 0) {
        return -1;
    }
    off = (size_t)ret;

    if (off + 4 > buf_cap) {
        return -1;
    }
    put_u16(buf, off, (uint16_t)qtype);
    put_u16(buf, off + 2, 1);
    off += 4;

    if (has_edns) {
        size_t opt_rdlen = 0;
        if (edns_opt_data != NULL && edns_opt_len > 0) {
            opt_rdlen = 4U + edns_opt_len;
        }
        if (off + 11U + opt_rdlen > buf_cap) {
            return -1;
        }
        buf[off++] = 0;
        put_u16(buf, off, 41);  off += 2;
        put_u16(buf, off, edns0_size ? edns0_size : 4096U);  off += 2;
        put_u32(buf, off, 0);   off += 4;
        put_u16(buf, off, (uint16_t)opt_rdlen);  off += 2;
        if (edns_opt_data != NULL && edns_opt_len > 0) {
            put_u16(buf, off, (uint16_t)EDNS0_TUNNEL_OPTION);  off += 2;
            put_u16(buf, off, (uint16_t)edns_opt_len);         off += 2;
            memcpy(buf + off, edns_opt_data, edns_opt_len);
            off += edns_opt_len;
        }
    }
    return (int)off;
}

/* ------------------------------------------------------------------ */
/* dns_build_response_ext                                               */
/* ------------------------------------------------------------------ */

int dns_build_response_ext(uint16_t id,
                           const char *question_fqdn, dns_type_t qtype,
                           const dns_response_ext_t *resp,
                           uint8_t *buf, size_t buf_cap)
{
    size_t   off = 0;
    size_t   i;
    int      ret;
    uint16_t arcount;
    int      has_edns;

    if (!resp || !buf || buf_cap < 12) {
        return -1;
    }

    has_edns = (resp->edns0_size > 0) ||
               (resp->edns_opt_data != NULL && resp->edns_opt_len > 0);
    arcount  = (uint16_t)(resp->num_addl + (has_edns ? 1U : 0U));

    put_u16(buf, 0,  id);
    put_u16(buf, 2,  0x8400U);
    put_u16(buf, 4,  1);
    put_u16(buf, 6,  (uint16_t)resp->num_answers);
    put_u16(buf, 8,  (uint16_t)resp->num_auth_ns);
    put_u16(buf, 10, arcount);
    off = 12;

    if (question_fqdn) {
        ret = encode_labels(question_fqdn, buf, buf_cap, off);
        if (ret < 0) return -1;
        off = (size_t)ret;
    } else {
        if (off >= buf_cap) return -1;
        buf[off++] = 0;
    }
    if (off + 4 > buf_cap) return -1;
    put_u16(buf, off, (uint16_t)qtype);
    put_u16(buf, off + 2, 1);
    off += 4;

    /* Answer section */
    for (i = 0; i < resp->num_answers; i++) {
        const dns_answer_t *ans   = &resp->answers[i];
        size_t              rdlen = ans->rdata_len;

        if (off + 2 > buf_cap) return -1;
        buf[off] = 0xC0U;  buf[off + 1] = 12;  off += 2;

        if (off + 10 > buf_cap) return -1;
        put_u16(buf, off, (uint16_t)ans->type);  off += 2;
        put_u16(buf, off, 1);                    off += 2;
        put_u32(buf, off, ans->ttl);             off += 4;

        if (ans->type == DNS_TYPE_TXT) {
            if (off + 2 + 1 + rdlen > buf_cap) return -1;
            put_u16(buf, off, (uint16_t)(1 + rdlen));  off += 2;
            buf[off++] = (uint8_t)rdlen;
            memcpy(buf + off, ans->rdata, rdlen);
            off += rdlen;
        } else {
            if (off + 2 + rdlen > buf_cap) return -1;
            put_u16(buf, off, (uint16_t)rdlen);  off += 2;
            if (rdlen > 0) { memcpy(buf + off, ans->rdata, rdlen); off += rdlen; }
        }
    }

    /* Authority section: NS records */
    for (i = 0; i < resp->num_auth_ns; i++) {
        const char *ns_name = resp->auth_ns_names[i];
        size_t      rdlen_off;
        size_t      rdata_start;

        if (off + 2 > buf_cap) return -1;
        buf[off] = 0xC0U;  buf[off + 1] = 12;  off += 2;

        if (off + 10 > buf_cap) return -1;
        put_u16(buf, off, (uint16_t)DNS_TYPE_NS);  off += 2;
        put_u16(buf, off, 1);                      off += 2;
        put_u32(buf, off, resp->auth_ns_ttl);      off += 4;

        rdlen_off  = off;
        off       += 2;  /* placeholder for RDLENGTH */
        rdata_start = off;

        ret = encode_labels(ns_name ? ns_name : ".", buf, buf_cap, off);
        if (ret < 0) return -1;
        off = (size_t)ret;
        put_u16(buf, rdlen_off, (uint16_t)(off - rdata_start));
    }

    /* Additional section */
    for (i = 0; i < resp->num_addl; i++) {
        const dns_answer_t *ans   = &resp->addl_records[i];
        size_t              rdlen = ans->rdata_len;

        if (off + 2 > buf_cap) return -1;
        buf[off] = 0xC0U;  buf[off + 1] = 12;  off += 2;

        if (off + 10 > buf_cap) return -1;
        put_u16(buf, off, (uint16_t)ans->type);  off += 2;
        put_u16(buf, off, 1);                    off += 2;
        put_u32(buf, off, ans->ttl);             off += 4;

        if (off + 2 + rdlen > buf_cap) return -1;
        put_u16(buf, off, (uint16_t)rdlen);  off += 2;
        if (rdlen > 0) { memcpy(buf + off, ans->rdata, rdlen); off += rdlen; }
    }

    /* EDNS0 OPT record */
    if (has_edns) {
        size_t opt_rdlen = 0;
        if (resp->edns_opt_data != NULL && resp->edns_opt_len > 0) {
            opt_rdlen = 4U + resp->edns_opt_len;
        }
        if (off + 11U + opt_rdlen > buf_cap) return -1;
        buf[off++] = 0;
        put_u16(buf, off, 41);  off += 2;
        put_u16(buf, off, resp->edns0_size ? resp->edns0_size : 4096U);  off += 2;
        put_u32(buf, off, 0);   off += 4;
        put_u16(buf, off, (uint16_t)opt_rdlen);  off += 2;
        if (resp->edns_opt_data != NULL && resp->edns_opt_len > 0) {
            put_u16(buf, off, (uint16_t)EDNS0_TUNNEL_OPTION);  off += 2;
            put_u16(buf, off, (uint16_t)resp->edns_opt_len);   off += 2;
            memcpy(buf + off, resp->edns_opt_data, resp->edns_opt_len);
            off += resp->edns_opt_len;
        }
    }
    return (int)off;
}

/* ------------------------------------------------------------------ */
/* dns_parse_response_full                                              */
/* ------------------------------------------------------------------ */

err_t dns_parse_response_full(const uint8_t *buf, size_t len,
                               dns_parsed_response_t *out)
{
    uint16_t qdcount, ancount, nscount, arcount;
    uint16_t counts[3];
    size_t   off = 0;
    uint16_t i;
    int      sect;
    char     name_tmp[512];
    int      ret;

    if (!buf || len < 12 || !out) {
        return ERR_PROTO;
    }

    memset(out, 0, sizeof(*out));
    out->txid = get_u16(buf, 0);
    qdcount   = get_u16(buf, 4);
    ancount   = get_u16(buf, 6);
    nscount   = get_u16(buf, 8);
    arcount   = get_u16(buf, 10);
    off       = 12;

    counts[0] = ancount;
    counts[1] = nscount;
    counts[2] = arcount;

    /* Skip questions */
    for (i = 0; i < qdcount; i++) {
        ret = decode_labels(buf, len, off, name_tmp, sizeof(name_tmp));
        if (ret < 0) return ERR_PROTO;
        off = (size_t)ret;
        if (off + 4 > len) return ERR_PROTO;
        if (i == 0) out->question_type = get_u16(buf, off);
        off += 4;
    }

    for (sect = 0; sect < 3; sect++) {
        for (i = 0; i < counts[sect]; i++) {
            uint16_t rtype, rdlen;
            uint32_t ttl;

            ret = decode_labels(buf, len, off, name_tmp, sizeof(name_tmp));
            if (ret < 0) return ERR_PROTO;
            off = (size_t)ret;

            if (off + 10 > len) return ERR_PROTO;
            rtype = get_u16(buf, off);  off += 2;
            off  += 2;  /* CLASS */
            ttl   = get_u32(buf, off);  off += 4;
            rdlen = get_u16(buf, off);  off += 2;
            if (off + rdlen > len) return ERR_PROTO;

            if (rtype == 41U) {
                /* EDNS0 OPT record — extract custom options */
                size_t opt_off = off;
                size_t opt_end = off + rdlen;
                while (opt_off + 4U <= opt_end) {
                    uint16_t opt_code = get_u16(buf, opt_off);  opt_off += 2;
                    uint16_t opt_len  = get_u16(buf, opt_off);  opt_off += 2;
                    if ((uint16_t)opt_code == (uint16_t)EDNS0_TUNNEL_OPTION) {
                        size_t copy_len = opt_len;
                        if (copy_len > sizeof(out->edns_opt)) {
                            copy_len = sizeof(out->edns_opt);
                        }
                        memcpy(out->edns_opt, buf + opt_off, copy_len);
                        out->edns_opt_len = copy_len;
                    }
                    if (opt_off + opt_len > opt_end) break;
                    opt_off += opt_len;
                }
            } else if (out->num_records < 128U) {
                dns_rr_t *rr    = &out->records[out->num_records++];
                size_t    cplen = rdlen;
                if (cplen > sizeof(rr->rdata)) cplen = sizeof(rr->rdata);
                rr->type    = (dns_type_t)rtype;
                rr->ttl     = ttl;
                rr->section = (uint8_t)sect;
                strncpy(rr->name, name_tmp, sizeof(rr->name) - 1);
                rr->name[sizeof(rr->name) - 1] = '\0';
                memcpy(rr->rdata, buf + off, cplen);
                rr->rdata_len = cplen;
            }
            off += rdlen;
        }
    }
    return ERR_OK;
}

/* ------------------------------------------------------------------ */
/* RDATA builders                                                       */
/* ------------------------------------------------------------------ */

int dns_build_naptr_rdata(uint16_t order, uint16_t pref,
                          const char *flags, const char *service,
                          const char *regexp, const char *replacement,
                          uint8_t *out, size_t out_cap)
{
    size_t off = 0;
    size_t slen;
    int    ret;

    if (!out || out_cap < 4) return -1;

    put_u16(out, 0, order);  off += 2;
    put_u16(out, 2, pref);   off += 2;

    /* flags */
    slen = flags ? strlen(flags) : 0U;
    if (off + 1U + slen > out_cap) return -1;
    out[off++] = (uint8_t)slen;
    if (slen > 0) { memcpy(out + off, flags, slen); off += slen; }

    /* service */
    slen = service ? strlen(service) : 0U;
    if (off + 1U + slen > out_cap) return -1;
    out[off++] = (uint8_t)slen;
    if (slen > 0) { memcpy(out + off, service, slen); off += slen; }

    /* regexp */
    slen = regexp ? strlen(regexp) : 0U;
    if (off + 1U + slen > out_cap) return -1;
    out[off++] = (uint8_t)slen;
    if (slen > 0) { memcpy(out + off, regexp, slen); off += slen; }

    /* replacement: DNS wire-format name */
    if (replacement && *replacement) {
        ret = encode_labels(replacement, out, out_cap, off);
        if (ret < 0) return -1;
        off = (size_t)ret;
    } else {
        if (off >= out_cap) return -1;
        out[off++] = 0;
    }
    return (int)off;
}

int dns_build_srv_rdata(uint16_t prio, uint16_t weight, uint16_t port,
                        const char *target,
                        uint8_t *out, size_t out_cap)
{
    size_t off = 0;
    int    ret;

    if (!out || out_cap < 6) return -1;

    put_u16(out, 0, prio);    off += 2;
    put_u16(out, 2, weight);  off += 2;
    put_u16(out, 4, port);    off += 2;

    if (target && *target) {
        ret = encode_labels(target, out, out_cap, off);
        if (ret < 0) return -1;
        off = (size_t)ret;
    } else {
        if (off >= out_cap) return -1;
        out[off++] = 0;
    }
    return (int)off;
}

int dns_build_caa_rdata(uint8_t flags, const char *tag, const char *value,
                        uint8_t *out, size_t out_cap)
{
    size_t off     = 0;
    size_t tag_len = tag   ? strlen(tag)   : 0U;
    size_t val_len = value ? strlen(value) : 0U;

    if (!out || out_cap < 2U + tag_len + val_len) return -1;

    out[off++] = flags;
    out[off++] = (uint8_t)tag_len;
    if (tag_len > 0) { memcpy(out + off, tag, tag_len); off += tag_len; }
    if (val_len > 0) { memcpy(out + off, value, val_len); off += val_len; }
    return (int)off;
}

int dns_build_soa_rdata(const char *mname, const char *rname,
                        uint32_t serial, uint32_t refresh,
                        uint32_t retry, uint32_t expire,
                        uint32_t minimum,
                        uint8_t *out, size_t out_cap)
{
    size_t off = 0;
    int    ret;

    if (!out || !mname || !rname) return -1;

    ret = encode_labels(mname, out, out_cap, off);
    if (ret < 0) return -1;
    off = (size_t)ret;

    ret = encode_labels(rname, out, out_cap, off);
    if (ret < 0) return -1;
    off = (size_t)ret;

    if (off + 20U > out_cap) return -1;
    put_u32(out, off, serial);   off += 4;
    put_u32(out, off, refresh);  off += 4;
    put_u32(out, off, retry);    off += 4;
    put_u32(out, off, expire);   off += 4;
    put_u32(out, off, minimum);  off += 4;
    return (int)off;
}

int dns_build_svcb_rdata(uint16_t priority, const char *target,
                         const uint8_t *params, size_t params_len,
                         uint8_t *out, size_t out_cap)
{
    size_t off = 0;
    int    ret;

    if (!out || out_cap < 2) return -1;

    put_u16(out, 0, priority);
    off = 2;

    if (target && *target) {
        ret = encode_labels(target, out, out_cap, off);
        if (ret < 0) return -1;
        off = (size_t)ret;
    } else {
        if (off >= out_cap) return -1;
        out[off++] = 0; /* root */
    }

    if (params && params_len > 0) {
        if (off + params_len > out_cap) return -1;
        memcpy(out + off, params, params_len);
        off += params_len;
    }
    return (int)off;
}

int dns_build_hinfo_rdata(const char *cpu, const char *os,
                          uint8_t *out, size_t out_cap)
{
    size_t off     = 0;
    size_t cpu_len = cpu ? strlen(cpu) : 0U;
    size_t os_len  = os  ? strlen(os)  : 0U;

    if (!out || out_cap < 2U + cpu_len + os_len) return -1;

    out[off++] = (uint8_t)cpu_len;
    if (cpu_len > 0) { memcpy(out + off, cpu, cpu_len); off += cpu_len; }
    out[off++] = (uint8_t)os_len;
    if (os_len > 0)  { memcpy(out + off, os,  os_len);  off += os_len; }
    return (int)off;
}
