#include "channel.h"
#include "encode.h"
#include "util.h"
#include <string.h>
#include <stdio.h>

/* ------------------------------------------------------------------ */
/* Internal helpers                                                     */
/* ------------------------------------------------------------------ */

/* Decode a wire-format DNS name starting at rdata[0], without following
 * compression pointers (safe for self-contained rdata).
 * Writes dotted-label string into out.  Returns bytes consumed on success
 * (i.e. the wire length of the name), or -1 on error. */
static int decode_name_noctx(const uint8_t *rdata, size_t rdata_len,
                              char *out, size_t out_cap)
{
    size_t i       = 0;
    size_t out_pos = 0;

    while (i < rdata_len) {
        uint8_t llen = rdata[i];
        if (llen == 0) {
            /* end of name */
            if (out_pos < out_cap) {
                out[out_pos] = '\0';
            }
            return (int)(i + 1);
        }
        if ((llen & 0xC0U) == 0xC0U) {
            /* compression pointer — not supported here */
            return -1;
        }
        if (llen > 63U) {
            return -1;
        }
        i++;
        if (i + llen > rdata_len) {
            return -1;
        }
        if (out_pos > 0) {
            if (out_pos >= out_cap - 1U) {
                return -1;
            }
            out[out_pos++] = '.';
        }
        if (out_pos + llen >= out_cap) {
            return -1;
        }
        memcpy(out + out_pos, rdata + i, llen);
        out_pos += llen;
        i       += llen;
    }
    if (out_pos < out_cap) {
        out[out_pos] = '\0';
    }
    return -1; /* missing root label */
}

/* Build NAPTR RDATA with binary regexp data.
 * order=1, pref=1, flags="U", service="E2U+tunnel", replacement=root.
 * The regexp field carries raw binary data (frag_data, frag_len bytes). */
static int build_naptr_rdata_bin(const uint8_t *frag_data, size_t frag_len,
                                  uint8_t *out, size_t out_cap)
{
    static const char svc[] = "E2U+tunnel";
    size_t            off   = 0;

    if (!out || frag_len > 252U) {
        return -1;
    }
    /* order (2) + pref (2) + flags_len (1) + 'U' (1) +
     * svc_len (1) + svc (10) + regexp_len (1) + frag_len + root (1) */
    if (out_cap < 18U + frag_len) {
        return -1;
    }

    out[off++] = 0; out[off++] = 1; /* order = 1 */
    out[off++] = 0; out[off++] = 1; /* pref  = 1 */
    out[off++] = 1; out[off++] = 'U';
    out[off++] = 10;
    memcpy(out + off, svc, 10); off += 10;
    out[off++] = (uint8_t)frag_len;
    if (frag_len > 0) {
        memcpy(out + off, frag_data, frag_len);
        off += frag_len;
    }
    out[off++] = 0; /* replacement = root */
    return (int)off;
}

/* Extract binary regexp field from NAPTR rdata.
 * Returns the length of the regexp content, or -1 on error.
 * Writes up to out_cap bytes into out. */
static int parse_naptr_regexp(const uint8_t *rdata, size_t rdata_len,
                               uint8_t *out, size_t out_cap)
{
    size_t  off  = 0;
    uint8_t slen;

    /* order (2) + pref (2) */
    if (rdata_len < 4U) {
        return -1;
    }
    off = 4;

    /* flags */
    if (off >= rdata_len) {
        return -1;
    }
    slen = rdata[off++];
    if (off + slen > rdata_len) {
        return -1;
    }
    off += slen;

    /* service */
    if (off >= rdata_len) {
        return -1;
    }
    slen = rdata[off++];
    if (off + slen > rdata_len) {
        return -1;
    }
    off += slen;

    /* regexp */
    if (off >= rdata_len) {
        return -1;
    }
    slen = rdata[off++];
    if ((size_t)slen < 3U) {
        return -1; /* need at least 3-byte fragment header */
    }
    if (off + slen > rdata_len) {
        return -1;
    }
    {
        size_t copy = slen;
        if (copy > out_cap) {
            copy = out_cap;
        }
        memcpy(out, rdata + off, copy);
    }
    return (int)slen;
}

/* Hex-encode src[0..len-1] into dst (needs 2*len+1 bytes). */
static void hex_encode(const uint8_t *src, size_t len, char *dst)
{
    static const char hx[] = "0123456789abcdef";
    size_t i;
    for (i = 0; i < len; i++) {
        dst[i * 2U]         = hx[(src[i] >> 4) & 0x0FU];
        dst[i * 2U + 1U]    = hx[src[i] & 0x0FU];
    }
    dst[len * 2U] = '\0';
}

/* Hex-decode src[0..src_len-1] into dst (needs src_len/2 bytes).
 * Returns number of bytes decoded, or -1. */
static int hex_decode(const char *src, size_t src_len,
                      uint8_t *dst, size_t dst_cap)
{
    size_t i;
    int    hi;
    int    lo;

    if (src_len % 2U != 0U) {
        return -1;
    }
    if (dst_cap < src_len / 2U) {
        return -1;
    }
    for (i = 0; i < src_len; i += 2U) {
        char c0 = src[i];
        char c1 = src[i + 1U];

        if (c0 >= '0' && c0 <= '9') {
            hi = c0 - '0';
        } else if (c0 >= 'a' && c0 <= 'f') {
            hi = 10 + (c0 - 'a');
        } else if (c0 >= 'A' && c0 <= 'F') {
            hi = 10 + (c0 - 'A');
        } else {
            return -1;
        }

        if (c1 >= '0' && c1 <= '9') {
            lo = c1 - '0';
        } else if (c1 >= 'a' && c1 <= 'f') {
            lo = 10 + (c1 - 'a');
        } else if (c1 >= 'A' && c1 <= 'F') {
            lo = 10 + (c1 - 'A');
        } else {
            return -1;
        }

        dst[i / 2U] = (uint8_t)((hi << 4) | lo);
    }
    return (int)(src_len / 2U);
}

/* Strip dots from a label string.  Writes into out[].
 * Returns bytes written, or -1. */
static int strip_dots(const char *in, size_t in_len,
                      char *out, size_t out_cap)
{
    size_t i;
    size_t j = 0;

    for (i = 0; i < in_len; i++) {
        if (in[i] != '.') {
            if (j >= out_cap - 1U) {
                return -1;
            }
            out[j++] = in[i];
        }
    }
    out[j] = '\0';
    return (int)j;
}

/* Place bytes from a headed fragment into out[].
 * header bytes: out_offset[1:0] big-endian, frag_len[2].
 * Returns 0 on success, -1 if out of bounds. */
static int place_fragment(const uint8_t *frag, size_t frag_total_len,
                           uint8_t *out, size_t out_cap,
                           size_t *high_water)
{
    uint16_t data_offset;
    uint8_t  frag_len;
    size_t   end;

    if (frag_total_len < 3U) {
        return -1;
    }
    data_offset = (uint16_t)(((uint16_t)frag[0] << 8) | frag[1]);
    frag_len    = frag[2];

    if ((size_t)frag_len != frag_total_len - 3U) {
        /* fragment_len field must match actual data bytes */
        frag_len = (uint8_t)(frag_total_len - 3U);
    }

    end = (size_t)data_offset + frag_len;
    if (end > out_cap) {
        return -1;
    }
    memcpy(out + data_offset, frag + 3U, frag_len);
    if (end > *high_water) {
        *high_water = end;
    }
    return 0;
}

/* ------------------------------------------------------------------ */
/* Public API                                                           */
/* ------------------------------------------------------------------ */

void channel_buf_init(channel_buf_t *cb, uint32_t active_channels,
                      const char *domain)
{
    memset(cb, 0, sizeof(*cb));
    cb->active_channels = active_channels;
    if (domain) {
        strncpy(cb->domain, domain, sizeof(cb->domain) - 1);
    }
    /* Wire up resp pointers */
    cb->resp.answers       = cb->answers;
    cb->resp.auth_ns_names = (const char **)cb->ns_name_ptrs;
    cb->resp.addl_records  = cb->addl;
    cb->resp.auth_ns_ttl   = 300;
    cb->resp.edns0_size    = 0;
}

int channel_pack(channel_buf_t *cb, const uint8_t *data, size_t data_len)
{
    size_t  packed = 0;
    int     i;
    uint8_t frag[512];   /* fragment header (3 bytes) + data chunk */
    char    encoded[1024];

    if (!cb || (!data && data_len > 0)) {
        return -1;
    }

    /* Reset counters */
    cb->num_answers = 0;
    cb->num_ns      = 0;
    cb->num_addl    = 0;
    cb->rdata_off   = 0;
    cb->edns_len    = 0;

    /* 1. NAPTR: up to 4 records, each carrying up to 240 bytes of data */
    if ((cb->active_channels & CHAN_NAPTR) && packed < data_len
            && cb->num_answers < CHANNEL_MAX_ANSWERS) {
        for (i = 0; i < 4 && packed < data_len
                 && cb->num_answers < CHANNEL_MAX_ANSWERS; i++) {
            size_t      avail  = data_len - packed;
            size_t      chunk  = (avail > 240U) ? 240U : avail;
            uint8_t    *rdata  = cb->rdata_buf + cb->rdata_off;
            size_t      remain = CHANNEL_RDATA_CAP - cb->rdata_off;
            int         rlen;
            dns_answer_t *ans;

            frag[0] = (uint8_t)(packed >> 8);
            frag[1] = (uint8_t)(packed & 0xFFU);
            frag[2] = (uint8_t)chunk;
            memcpy(frag + 3U, data + packed, chunk);

            rlen = build_naptr_rdata_bin(frag, 3U + chunk, rdata, remain);
            if (rlen < 0) {
                break;
            }
            cb->rdata_off += (size_t)rlen;

            ans            = &cb->answers[cb->num_answers++];
            ans->type      = DNS_TYPE_NAPTR;
            ans->rdata     = rdata;
            ans->rdata_len = (size_t)rlen;
            ans->ttl       = 300;
            packed        += chunk;
        }
    }

    /* 2. SOA: 1 record, data encoded as base36 labels in mname */
    if ((cb->active_channels & CHAN_SOA_DATA) && packed < data_len
            && cb->num_answers < CHANNEL_MAX_ANSWERS) {
        size_t        avail  = data_len - packed;
        /* mname can carry encoded data of ~140 bytes after domain suffix */
        size_t        chunk  = (avail > 136U) ? 136U : avail;
        size_t        total  = 3U + chunk;          /* header + data */
        int           enc;
        char          labels[512];
        char          mname[768];
        uint8_t      *rdata  = cb->rdata_buf + cb->rdata_off;
        size_t        remain = CHANNEL_RDATA_CAP - cb->rdata_off;
        int           rlen;
        dns_answer_t *ans;

        frag[0] = (uint8_t)(packed >> 8);
        frag[1] = (uint8_t)(packed & 0xFFU);
        frag[2] = (uint8_t)chunk;
        memcpy(frag + 3U, data + packed, chunk);

        enc = encode_to_labels(frag, total, labels, sizeof(labels),
                               ENCODE_BASE36);
        if (enc >= 0) {
            if ((size_t)enc + strlen(cb->domain) + 2U < sizeof(mname)) {
                if (enc > 0) {
                    snprintf(mname, sizeof(mname), "%s.%s", labels,
                             cb->domain);
                } else {
                    snprintf(mname, sizeof(mname), "%s", cb->domain);
                }

                rlen = dns_build_soa_rdata(mname, "hostmaster.example.com",
                                            1U, 86400U, 3600U, 604800U, 300U,
                                            rdata, remain);
                if (rlen >= 0) {
                    cb->rdata_off += (size_t)rlen;
                    ans            = &cb->answers[cb->num_answers++];
                    ans->type      = DNS_TYPE_SOA;
                    ans->rdata     = rdata;
                    ans->rdata_len = (size_t)rlen;
                    ans->ttl       = 300;
                    packed        += chunk;
                }
            }
        }
    }

    /* 3. CAA: 1 record, hex-encoded fragment in value field */
    if ((cb->active_channels & CHAN_CAA) && packed < data_len
            && cb->num_answers < CHANNEL_MAX_ANSWERS) {
        size_t        avail  = data_len - packed;
        size_t        chunk  = (avail > 240U) ? 240U : avail;
        size_t        total  = 3U + chunk;
        char          hexval[512];
        uint8_t      *rdata  = cb->rdata_buf + cb->rdata_off;
        size_t        remain = CHANNEL_RDATA_CAP - cb->rdata_off;
        int           rlen;
        dns_answer_t *ans;

        frag[0] = (uint8_t)(packed >> 8);
        frag[1] = (uint8_t)(packed & 0xFFU);
        frag[2] = (uint8_t)chunk;
        memcpy(frag + 3U, data + packed, chunk);

        hex_encode(frag, total, hexval);

        rlen = dns_build_caa_rdata(0, "issue", hexval, rdata, remain);
        if (rlen >= 0) {
            cb->rdata_off += (size_t)rlen;
            ans            = &cb->answers[cb->num_answers++];
            ans->type      = DNS_TYPE_CAA;
            ans->rdata     = rdata;
            ans->rdata_len = (size_t)rlen;
            ans->ttl       = 300;
            packed        += chunk;
        }
    }

    /* 4. SRV: 1 record, 6 raw bytes (no fragment header) */
    if ((cb->active_channels & CHAN_SRV) && packed < data_len
            && cb->num_answers < CHANNEL_MAX_ANSWERS) {
        size_t        avail   = data_len - packed;
        size_t        chunk   = (avail > 6U) ? 6U : avail;
        uint8_t       bytes[6];
        uint16_t      prio;
        uint16_t      weight;
        uint16_t      port;
        uint8_t      *rdata  = cb->rdata_buf + cb->rdata_off;
        size_t        remain = CHANNEL_RDATA_CAP - cb->rdata_off;
        int           rlen;
        dns_answer_t *ans;

        memset(bytes, 0, sizeof(bytes));
        memcpy(bytes, data + packed, chunk);
        prio   = (uint16_t)(((uint16_t)bytes[0] << 8) | bytes[1]);
        weight = (uint16_t)(((uint16_t)bytes[2] << 8) | bytes[3]);
        port   = (uint16_t)(((uint16_t)bytes[4] << 8) | bytes[5]);

        rlen = dns_build_srv_rdata(prio, weight, port, ".", rdata, remain);
        if (rlen >= 0) {
            cb->rdata_off += (size_t)rlen;
            ans            = &cb->answers[cb->num_answers++];
            ans->type      = DNS_TYPE_SRV;
            ans->rdata     = rdata;
            ans->rdata_len = (size_t)rlen;
            ans->ttl       = 300;
            packed        += chunk;
        }
    }

    /* 5. Auth NS: up to CHANNEL_MAX_NS records, base36 label data */
    if ((cb->active_channels & CHAN_AUTH_NS) && packed < data_len) {
        int ns_i;
        for (ns_i = 0; ns_i < (int)CHANNEL_MAX_NS && packed < data_len
                 && cb->num_ns < CHANNEL_MAX_NS; ns_i++) {
            size_t avail = data_len - packed;
            size_t chunk = (avail > 60U) ? 60U : avail;
            int    enc;

            frag[0] = (uint8_t)(packed >> 8);
            frag[1] = (uint8_t)(packed & 0xFFU);
            frag[2] = (uint8_t)chunk;
            memcpy(frag + 3U, data + packed, chunk);

            enc = encode_to_labels(frag, 3U + chunk, encoded,
                                   sizeof(encoded), ENCODE_BASE36);
            if (enc < 0) {
                break;
            }

            snprintf(cb->ns_names[cb->num_ns],
                     sizeof(cb->ns_names[0]),
                     "%.100s.ns%d.%.100s", encoded, ns_i, cb->domain);
            cb->ns_name_ptrs[cb->num_ns] = cb->ns_names[cb->num_ns];
            cb->num_ns++;
            packed += chunk;
        }
    }

    /* 6. Additional A records: 4 raw bytes each (no fragment header) */
    if ((cb->active_channels & CHAN_ADDL_GLUE) && packed < data_len) {
        int ai;
        for (ai = 0; ai < (int)CHANNEL_MAX_ADDL && packed < data_len
                 && cb->num_addl < CHANNEL_MAX_ADDL; ai++) {
            size_t        avail   = data_len - packed;
            size_t        chunk   = (avail > 4U) ? 4U : avail;
            uint8_t       ip[4];
            uint8_t      *rdata;
            dns_answer_t *addl;

            if (cb->rdata_off + 4U > CHANNEL_RDATA_CAP) {
                break;
            }
            rdata = cb->rdata_buf + cb->rdata_off;
            memset(ip, 0, sizeof(ip));
            memcpy(ip, data + packed, chunk);
            memcpy(rdata, ip, 4U);
            cb->rdata_off += 4U;

            addl            = &cb->addl[cb->num_addl++];
            addl->type      = DNS_TYPE_A;
            addl->rdata     = rdata;
            addl->rdata_len = 4;
            addl->ttl       = 300;
            packed         += chunk;
        }
    }

    /* 7. EDNS0: up to 200 bytes of raw data (with 3-byte header) */
    if ((cb->active_channels & CHAN_EDNS_OPT) && packed < data_len) {
        size_t avail = data_len - packed;
        size_t chunk = (avail > 197U) ? 197U : avail;

        frag[0] = (uint8_t)(packed >> 8);
        frag[1] = (uint8_t)(packed & 0xFFU);
        frag[2] = (uint8_t)chunk;
        if (3U + chunk <= sizeof(cb->edns_buf)) {
            memcpy(cb->edns_buf, frag, 3U);
            memcpy(cb->edns_buf + 3U, data + packed, chunk);
            cb->edns_len = 3U + chunk;
            packed      += chunk;
        }
    }

    /* 8. TTL steganography: 3 raw bytes per answer record */
    if ((cb->active_channels & CHAN_TTL_DATA) && packed < data_len) {
        size_t ai;
        for (ai = 0; ai < cb->num_answers && packed + 3U <= data_len; ai++) {
            cb->answers[ai].ttl =
                ((uint32_t)data[packed]     << 16) |
                ((uint32_t)data[packed + 1] <<  8) |
                 (uint32_t)data[packed + 2];
            packed += 3;
        }
    }

    /* 9. TXT fallback: if nothing has been packed yet */
    if (cb->num_answers == 0 && packed < data_len) {
        size_t        avail  = data_len - packed;
        size_t        chunk  = (avail > 255U) ? 255U : avail;
        uint8_t      *rdata  = cb->rdata_buf + cb->rdata_off;
        size_t        remain = CHANNEL_RDATA_CAP - cb->rdata_off;
        dns_answer_t *ans;

        if (remain >= chunk) {
            memcpy(rdata, data + packed, chunk);
            cb->rdata_off += chunk;
            ans            = &cb->answers[cb->num_answers++];
            ans->type      = DNS_TYPE_TXT;
            ans->rdata     = rdata;
            ans->rdata_len = chunk;
            ans->ttl       = 300;
            packed        += chunk;
        }
    }

    /* Populate resp */
    cb->resp.answers       = cb->answers;
    cb->resp.num_answers   = cb->num_answers;
    cb->resp.auth_ns_names = (const char **)cb->ns_name_ptrs;
    cb->resp.num_auth_ns   = cb->num_ns;
    cb->resp.auth_ns_ttl   = 300;
    cb->resp.addl_records  = cb->addl;
    cb->resp.num_addl      = cb->num_addl;

    if (cb->edns_len > 0) {
        cb->resp.edns_opt_data = cb->edns_buf;
        cb->resp.edns_opt_len  = cb->edns_len;
        cb->resp.edns0_size    = 4096;
    } else {
        cb->resp.edns_opt_data = NULL;
        cb->resp.edns_opt_len  = 0;
        cb->resp.edns0_size    = 0;
    }

    return (int)packed;
}

int channel_unpack(const dns_parsed_response_t *parsed,
                   uint32_t active_channels,
                   uint8_t *out, size_t out_cap)
{
    size_t       i;
    size_t       high_water = 0;
    uint8_t      frag_buf[512];

    if (!parsed || !out || out_cap == 0) {
        return -1;
    }

    memset(out, 0, out_cap);

    for (i = 0; i < parsed->num_records; i++) {
        const dns_rr_t *rr = &parsed->records[i];

        /* NAPTR in answer section */
        if (rr->section == 0 && rr->type == DNS_TYPE_NAPTR
                && (active_channels & CHAN_NAPTR)) {
            int flen = parse_naptr_regexp(rr->rdata, rr->rdata_len,
                                          frag_buf, sizeof(frag_buf));
            if (flen >= 3) {
                place_fragment(frag_buf, (size_t)flen, out, out_cap,
                               &high_water);
            }
            continue;
        }

        /* SOA in answer section */
        if (rr->section == 0 && rr->type == DNS_TYPE_SOA
                && (active_channels & CHAN_SOA_DATA)) {
            char    mname[512];
            int     wire_consumed;
            char    b36[512];
            int     slen;
            uint8_t decoded[256];
            int     dlen;
            char   *ns_pos;

            wire_consumed = decode_name_noctx(rr->rdata, rr->rdata_len,
                                               mname, sizeof(mname));
            if (wire_consumed < 0) {
                continue;
            }
            ns_pos = strstr(mname, ".ns");
            if (!ns_pos) {
                ns_pos = mname + strlen(mname);
            }
            *ns_pos = '\0';

            slen = strip_dots(mname, strlen(mname), b36, sizeof(b36));
            if (slen <= 0) {
                continue;
            }
            dlen = decode_data(b36, (size_t)slen, decoded, sizeof(decoded),
                               ENCODE_BASE36);
            if (dlen >= 3) {
                place_fragment(decoded, (size_t)dlen, out, out_cap,
                               &high_water);
            }
            continue;
        }

        /* CAA in answer section */
        if (rr->section == 0 && rr->type == DNS_TYPE_CAA
                && (active_channels & CHAN_CAA)) {
            /* CAA rdata: flags(1) + tag_len(1) + tag(tag_len) + value */
            size_t val_off;
            size_t val_len;
            int    dlen;

            if (rr->rdata_len < 2U) {
                continue;
            }
            val_off = 2U + rr->rdata[1];
            if (val_off >= rr->rdata_len) {
                continue;
            }
            val_len = rr->rdata_len - val_off;
            dlen    = hex_decode((const char *)(rr->rdata + val_off),
                                  val_len, frag_buf, sizeof(frag_buf));
            if (dlen >= 3) {
                place_fragment(frag_buf, (size_t)dlen, out, out_cap,
                               &high_water);
            }
            continue;
        }

        /* SRV in answer section: 6 raw bytes (no header) */
        if (rr->section == 0 && rr->type == DNS_TYPE_SRV
                && (active_channels & CHAN_SRV)) {
            if (rr->rdata_len >= 6U && high_water + 6U <= out_cap) {
                memcpy(out + high_water, rr->rdata, 6U);
                high_water += 6U;
            }
            continue;
        }

        /* Authority NS: base36 encoded data in first label(s) */
        if (rr->section == 1 && rr->type == DNS_TYPE_NS
                && (active_channels & CHAN_AUTH_NS)) {
            char   ns_name[512];
            char  *dot_ns;
            char   b36[512];
            int    slen;
            uint8_t decoded[256];
            int    dlen;
            int    wire_consumed;

            wire_consumed = decode_name_noctx(rr->rdata, rr->rdata_len,
                                               ns_name, sizeof(ns_name));
            if (wire_consumed < 0) {
                continue;
            }
            /* Find ".ns" to isolate the encoded prefix */
            dot_ns = strstr(ns_name, ".ns");
            if (!dot_ns) {
                continue;
            }
            *dot_ns = '\0';

            slen = strip_dots(ns_name, strlen(ns_name), b36, sizeof(b36));
            if (slen <= 0) {
                continue;
            }
            dlen = decode_data(b36, (size_t)slen, decoded, sizeof(decoded),
                               ENCODE_BASE36);
            if (dlen >= 3) {
                place_fragment(decoded, (size_t)dlen, out, out_cap,
                               &high_water);
            }
            continue;
        }

        /* Additional A records: 4 raw bytes each (no header) */
        if (rr->section == 2 && rr->type == DNS_TYPE_A
                && (active_channels & CHAN_ADDL_GLUE)) {
            if (rr->rdata_len >= 4U && high_water + 4U <= out_cap) {
                memcpy(out + high_water, rr->rdata, 4U);
                high_water += 4U;
            }
            continue;
        }

        /* TTL steganography: 3 raw bytes per answer record */
        if (rr->section == 0 && (active_channels & CHAN_TTL_DATA)) {
            if (high_water + 3U <= out_cap) {
                uint32_t t = rr->ttl & 0x00FFFFFFU;
                out[high_water]     = (uint8_t)(t >> 16);
                out[high_water + 1] = (uint8_t)(t >>  8);
                out[high_water + 2] = (uint8_t)(t & 0xFFU);
                high_water += 3U;
            }
            continue;
        }
    }

    /* EDNS0 option data */
    if ((active_channels & CHAN_EDNS_OPT) && parsed->edns_opt_len >= 3U) {
        place_fragment(parsed->edns_opt, parsed->edns_opt_len, out, out_cap,
                       &high_water);
    }

    return (int)high_water;
}
