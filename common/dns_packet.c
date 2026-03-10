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
