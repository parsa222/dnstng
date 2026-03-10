#include "tunnel_server.h"
#include "encode.h"
#include "log.h"
#include "transport.h"
#include <string.h>
#include <stdlib.h>
#include <stdio.h>

/* Session timeout: 5 minutes of inactivity */
#define SESSION_TIMEOUT_MS (5ULL * 60ULL * 1000ULL)
#define CLEANUP_INTERVAL_MS 30000ULL

/* ------------------------------------------------------------------ */
/* Forward declarations                                                 */
/* ------------------------------------------------------------------ */

static void on_dns_query(uint16_t query_id, const char *fqdn,
                          dns_type_t qtype,
                          const struct sockaddr *from, socklen_t from_len,
                          void *userdata);

static void cleanup_timer_cb(uv_timer_t *timer);

/* ------------------------------------------------------------------ */
/* Session management                                                   */
/* ------------------------------------------------------------------ */

static server_session_t *find_session(tunnel_server_t *ts, uint16_t sid)
{
    size_t i;
    for (i = 0; i < MAX_SESSIONS; i++) {
        if (ts->sessions[i].session_id == sid &&
            ts->sessions[i].state != SERVER_SESSION_NEW) {
            return &ts->sessions[i];
        }
    }
    return NULL;
}

static server_session_t *alloc_session(tunnel_server_t *ts, uint16_t sid)
{
    size_t i;
    for (i = 0; i < MAX_SESSIONS; i++) {
        if (ts->sessions[i].state == SERVER_SESSION_NEW) {
            server_session_t *s = &ts->sessions[i];
            memset(s, 0, sizeof(*s));
            s->session_id        = sid;
            s->state             = SERVER_SESSION_ACTIVE;
            s->last_activity_ms  = get_time_ms();
            transport_init(&s->transport);
            return s;
        }
    }
    return NULL;
}

/* ------------------------------------------------------------------ */
/* FQDN parsing
 * Format: {encoded_data_labels}.{session_id_4hex}.t.{domain}
 * Example: "abcdef.0001.t.tunnel.example.com"
 * The encoded_data_labels portion contains dot-separated labels up to
 * the session_id label (4 hex chars).
 * ------------------------------------------------------------------ */

static int parse_tunnel_fqdn(const char *fqdn, const char *domain,
                               uint16_t *session_id_out,
                               char *encoded_out, size_t encoded_cap)
{
    size_t fqdn_len   = strlen(fqdn);
    /* suffix: ".t.{domain}" */
    char   suffix[320];
    size_t suffix_len;
    const char *p;
    const char *session_start;
    const char *encoded_end;
    size_t session_len;
    char   session_hex[8];
    unsigned long sid;

    snprintf(suffix, sizeof(suffix), ".t.%s", domain);
    suffix_len = strlen(suffix);

    if (fqdn_len <= suffix_len) {
        return -1;
    }

    /* fqdn must end with suffix */
    if (strncasecmp(fqdn + fqdn_len - suffix_len,
                     suffix, suffix_len) != 0) {
        return -1;
    }

    /* The part before the suffix is: {encoded_labels}.{session_4hex} */
    p = fqdn;
    /* Find the last dot before the suffix */
    /* e.g. "abc.def.0001.t.tunnel.example.com"
     *                   ^ suffix starts here (after "0001")
     *       position of "0001" is fqdn_len - suffix_len - 4 (= 4 hex chars) */

    /* Find session_id: it's the label immediately before ".t.{domain}" */
    /* The char before suffix is fqdn[fqdn_len - suffix_len - 1] which
     * is the last char of the session label.
     * We look backwards for the dot separating session from encoded data. */
    {
        const char *suffix_start = fqdn + fqdn_len - suffix_len;
        const char *dot;

        /* suffix_start[-1] is last char before suffix_len */
        /* Find the dot before the session id label */
        dot = NULL;
        {
            const char *scan = suffix_start - 1;
            while (scan > fqdn) {
                scan--;
                if (*scan == '.') {
                    dot = scan;
                    break;
                }
            }
        }

        if (dot) {
            /* session_id is from dot+1 to suffix_start */
            session_start = dot + 1;
            session_len   = (size_t)(suffix_start - session_start);
            encoded_end   = dot;
        } else {
            /* No dot: entire prefix is session id (no encoded data) */
            session_start = p;
            session_len   = (size_t)(suffix_start - p);
            encoded_end   = p;
        }

        if (session_len != 4) {
            return -1;
        }

        memcpy(session_hex, session_start, 4);
        session_hex[4] = '\0';
        sid = strtoul(session_hex, NULL, 16);
        *session_id_out = (uint16_t)sid;

        /* encoded part: from fqdn to encoded_end */
        {
            size_t enc_len = (size_t)(encoded_end - fqdn);
            if (enc_len >= encoded_cap) {
                return -1;
            }
            if (enc_len > 0) {
                memcpy(encoded_out, fqdn, enc_len);
            }
            encoded_out[enc_len] = '\0';
        }
    }

    return 0;
}

/* ------------------------------------------------------------------ */
/* DNS query callback                                                   */
/* ------------------------------------------------------------------ */

static void on_dns_query(uint16_t query_id, const char *fqdn,
                          dns_type_t qtype,
                          const struct sockaddr *from, socklen_t from_len,
                          void *userdata)
{
    tunnel_server_t  *ts = (tunnel_server_t *)userdata;
    uint16_t          session_id;
    char              encoded[512];
    server_session_t *sess;
    uint8_t           pkt_buf[512];
    int               pkt_len;
    const char       *suffix_check;

    /* Is this a "check" query? */
    suffix_check = strstr(fqdn, "check.t.");
    if (suffix_check) {
        /* Respond with a simple TXT record */
        static const uint8_t ok_data[] = "ok";
        dns_server_respond(&ts->dns, query_id, fqdn, qtype,
                            from, from_len, ok_data, 2);
        return;
    }

    if (parse_tunnel_fqdn(fqdn, ts->cfg.domain,
                           &session_id, encoded, sizeof(encoded)) != 0) {
        /* Not a valid tunnel query - NXDOMAIN */
        return;
    }

    sess = find_session(ts, session_id);

    /* Decode the data portion */
    {
        uint8_t  decoded[512];
        int      dec_len = 0;

        if (encoded[0] != '\0' &&
            strncmp(encoded, "poll", 4) != 0) {
            dec_len = decode_from_labels(encoded, strlen(encoded),
                                          decoded, sizeof(decoded),
                                          ENCODE_BASE32);
        }

        if (dec_len > 0) {
            tunnel_header_t  hdr;
            const uint8_t   *payload;
            size_t           payload_len;
            err_t            e;

            e = transport_parse_packet(decoded, (size_t)dec_len,
                                        &hdr, &payload, &payload_len);
            if (e == ERR_OK) {
                /* SYN: create session */
                if ((hdr.flags & TUNNEL_FLAG_SYN) && !sess) {
                    sess = alloc_session(ts, session_id);
                    if (sess) {
                        memcpy(&sess->client_addr, from, from_len);
                        sess->client_addr_len = from_len;
                        LOG_INFO("New session 0x%04x from client", session_id);
                    }
                }

                if (sess) {
                    sess->last_activity_ms = get_time_ms();
                    transport_ack(&sess->transport, hdr.seq_num);

                    /* FIN: close session */
                    if (hdr.flags & TUNNEL_FLAG_FIN) {
                        sess->state = SERVER_SESSION_CLOSING;
                    }
                }
            }
        } else if (sess) {
            sess->last_activity_ms = get_time_ms();
        }
    }

    /* Build response: ACK packet */
    if (!sess) {
        /* Session not found: send RST-like empty response */
        uint8_t empty = 0;
        dns_server_respond(&ts->dns, query_id, fqdn, qtype,
                            from, from_len, &empty, 1);
        return;
    }

    pkt_len = transport_build_packet(&sess->transport, session_id,
                                      TUNNEL_FLAG_ACK,
                                      NULL, 0, pkt_buf, sizeof(pkt_buf));
    if (pkt_len > 0) {
        char  resp_labels[512];
        int   encoded_labels_len;
        uint8_t resp_data[512];
        int     resp_data_len;

        encoded_labels_len = encode_to_labels(pkt_buf, (size_t)pkt_len,
                                  resp_labels, sizeof(resp_labels),
                                  ENCODE_BASE32);

        if (encoded_labels_len > 0) {
            resp_data_len = encoded_labels_len;
            if (resp_data_len > (int)sizeof(resp_data)) {
                resp_data_len = (int)sizeof(resp_data);
            }
            memcpy(resp_data, resp_labels, (size_t)resp_data_len);
        } else {
            resp_data[0]  = 0;
            resp_data_len = 1;
        }

        dns_server_respond(&ts->dns, query_id, fqdn, qtype,
                            from, from_len,
                            resp_data, (size_t)resp_data_len);
    }
}

/* ------------------------------------------------------------------ */
/* Cleanup timer                                                        */
/* ------------------------------------------------------------------ */

static void cleanup_timer_cb(uv_timer_t *timer)
{
    tunnel_server_t *ts   = (tunnel_server_t *)timer->data;
    uint64_t         now  = get_time_ms();
    size_t           i;

    for (i = 0; i < MAX_SESSIONS; i++) {
        server_session_t *s = &ts->sessions[i];
        if (s->state == SERVER_SESSION_NEW) {
            continue;
        }
        if ((now - s->last_activity_ms) > SESSION_TIMEOUT_MS ||
            s->state == SERVER_SESSION_CLOSING) {
            LOG_DEBUG("Removing session 0x%04x (idle/closed)", s->session_id);
            transport_free(&s->transport);
            memset(s, 0, sizeof(*s));
        }
    }
}

/* ------------------------------------------------------------------ */
/* Public API                                                           */
/* ------------------------------------------------------------------ */

err_t tunnel_server_init(tunnel_server_t *ts, uv_loop_t *loop,
                          const server_config_t *cfg)
{
    err_t e;

    if (!ts || !loop || !cfg) {
        return ERR_INVAL;
    }

    memset(ts, 0, sizeof(*ts));
    ts->loop = loop;
    ts->cfg  = *cfg;

    e = dns_server_init(&ts->dns, loop,
                         cfg->bind_addr, cfg->bind_port,
                         cfg->domain);
    if (e != ERR_OK) {
        return e;
    }

    ts->dns.on_query  = on_dns_query;
    ts->dns.userdata  = ts;

    return ERR_OK;
}

err_t tunnel_server_start(tunnel_server_t *ts)
{
    err_t e;

    if (!ts) {
        return ERR_INVAL;
    }

    e = dns_server_start(&ts->dns);
    if (e != ERR_OK) {
        return e;
    }

    uv_timer_init(ts->loop, &ts->cleanup_timer);
    ts->cleanup_timer.data = ts;
    uv_timer_start(&ts->cleanup_timer, cleanup_timer_cb,
                   CLEANUP_INTERVAL_MS, CLEANUP_INTERVAL_MS);

    return ERR_OK;
}

void tunnel_server_stop(tunnel_server_t *ts)
{
    if (!ts) {
        return;
    }
    uv_timer_stop(&ts->cleanup_timer);
    dns_server_stop(&ts->dns);
}

void tunnel_server_free(tunnel_server_t *ts)
{
    size_t i;

    if (!ts) {
        return;
    }

    for (i = 0; i < MAX_SESSIONS; i++) {
        if (ts->sessions[i].state != SERVER_SESSION_NEW) {
            transport_free(&ts->sessions[i].transport);
        }
    }
}
