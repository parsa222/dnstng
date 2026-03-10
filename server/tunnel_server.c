#include "tunnel_server.h"
#include "encode.h"
#include "log.h"
#include "transport.h"
#include "channel.h"
#include "chain.h"
#include <string.h>
#include <stdlib.h>
#include <stdio.h>

/* Session timeout: 5 minutes of inactivity */
#define SESSION_TIMEOUT_MS (5ULL * 60ULL * 1000ULL)
#define CLEANUP_INTERVAL_MS 30000ULL

/* Lazy mode: max time to hold a pending query before responding (ms).
 * iodine uses 4-5 seconds; we use 4 seconds to stay under most
 * recursive resolver timeouts (typically 5-10 seconds per RFC 1035). */
#define LAZY_TIMEOUT_MS 4000ULL

/* Lazy drain timer interval (ms) */
#define LAZY_DRAIN_INTERVAL_MS 500ULL

/* ------------------------------------------------------------------ */
/* Forward declarations                                                 */
/* ------------------------------------------------------------------ */

static void on_dns_query(uint16_t query_id, const char *fqdn,
                          dns_type_t qtype,
                          const struct sockaddr *from, socklen_t from_len,
                          void *userdata);

static void cleanup_timer_cb(uv_timer_t *timer);
static void lazy_timer_cb(uv_timer_t *timer);

/* ------------------------------------------------------------------ */
/* Lazy mode helpers (iodine-inspired)                                  */
/* ------------------------------------------------------------------ */

/* Queue a DNS query for lazy-mode delayed response */
static void lazy_enqueue(server_session_t *sess,
                          uint16_t query_id, const char *fqdn,
                          uint16_t query_type,
                          const struct sockaddr *from, socklen_t from_len)
{
    int                slot = -1;
    int                oldest_slot = -1;
    uint64_t           oldest_time = UINT64_MAX;
    int                i;

    /* Find an empty slot, or evict the oldest */
    for (i = 0; i < LAZY_QUEUE_SIZE; i++) {
        if (!sess->pending[i].valid) {
            slot = i;
            break;
        }
        if (sess->pending[i].received_ms < oldest_time) {
            oldest_time = sess->pending[i].received_ms;
            oldest_slot = i;
        }
    }

    if (slot == -1) {
        /* Queue full: evict oldest (it will timeout anyway) */
        slot = oldest_slot;
    }

    sess->pending[slot].query_id   = query_id;
    strncpy(sess->pending[slot].question_fqdn, fqdn,
            sizeof(sess->pending[slot].question_fqdn) - 1);
    sess->pending[slot].question_fqdn[sizeof(sess->pending[slot].question_fqdn) - 1] = '\0';
    sess->pending[slot].query_type = query_type;
    memcpy(&sess->pending[slot].client_addr, from, from_len);
    sess->pending[slot].client_addr_len = from_len;
    sess->pending[slot].received_ms = get_time_ms();
    sess->pending[slot].valid       = 1;
    sess->pending_count++;
}

/* Get the oldest pending query (for responding). Returns NULL if none. */
static pending_query_t *lazy_dequeue(server_session_t *sess)
{
    int      oldest_slot = -1;
    uint64_t oldest_time = UINT64_MAX;
    int      i;

    for (i = 0; i < LAZY_QUEUE_SIZE; i++) {
        if (sess->pending[i].valid &&
            sess->pending[i].received_ms < oldest_time) {
            oldest_time = sess->pending[i].received_ms;
            oldest_slot = i;
        }
    }

    if (oldest_slot >= 0) {
        return &sess->pending[oldest_slot];
    }
    return NULL;
}

/* Mark a pending query as consumed */
static void lazy_consume(server_session_t *sess, pending_query_t *pq)
{
    pq->valid = 0;
    if (sess->pending_count > 0) {
        sess->pending_count--;
    }
}

/* Send a response to the oldest pending query using given data */
static void lazy_respond(tunnel_server_t *ts, server_session_t *sess,
                          const uint8_t *pkt_buf, size_t pkt_len);

/* Build and send a DNS response for the given transport packet */
static void send_tunnel_response(tunnel_server_t *ts,
                                  server_session_t *sess,
                                  uint16_t query_id, const char *fqdn,
                                  uint16_t query_type,
                                  const struct sockaddr *from,
                                  socklen_t from_len,
                                  const uint8_t *pkt_buf, size_t pkt_len);

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
/* Response building (shared by immediate and lazy-mode paths)          */
/* ------------------------------------------------------------------ */

static void send_tunnel_response(tunnel_server_t *ts,
                                  server_session_t *sess,
                                  uint16_t query_id, const char *fqdn,
                                  uint16_t query_type,
                                  const struct sockaddr *from,
                                  socklen_t from_len,
                                  const uint8_t *pkt_buf, size_t pkt_len)
{
    uint8_t resp_wire[4096];
    int     resp_len = -1;

    /* Use CNAME chaining if negotiated and configured */
    if ((sess->transport.active_channels & CHAN_CNAME_CHAIN) &&
            ts->cfg.cname_chain_depth > 0) {
        resp_len = chain_build_cname(query_id, fqdn,
                                      ts->cfg.domain,
                                      pkt_buf, pkt_len,
                                      ts->cfg.cname_chain_depth,
                                      resp_wire, sizeof(resp_wire));
    }
    /* Use NS referral chaining if CNAME not used and NS negotiated */
    else if ((sess->transport.active_channels & CHAN_NS_CHAIN) &&
              ts->cfg.ns_chain_depth > 0) {
        resp_len = chain_build_ns_referral(query_id, fqdn,
                                            ts->cfg.domain,
                                            pkt_buf, pkt_len,
                                            ts->cfg.ns_chain_depth,
                                            resp_wire, sizeof(resp_wire));
    }
    /* Use multi-channel packing */
    else if (sess->transport.active_channels != 0) {
        channel_buf_t cb;
        channel_buf_init(&cb, sess->transport.active_channels,
                         ts->cfg.domain);
        if (channel_pack(&cb, pkt_buf, pkt_len) > 0) {
            resp_len = dns_build_response_ext(query_id, fqdn,
                                               (dns_type_t)query_type,
                                               &cb.resp,
                                               resp_wire,
                                               sizeof(resp_wire));
        }
    }

    if (resp_len > 0) {
        dns_server_send_raw(&ts->dns, resp_wire, (size_t)resp_len,
                            from, from_len);
    } else {
        /* Fallback: plain TXT response */
        char    resp_labels[512];
        int     encoded_labels_len;
        uint8_t resp_data[512];
        int     resp_data_len;

        encoded_labels_len = encode_to_labels(pkt_buf, pkt_len,
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

        dns_server_respond(&ts->dns, query_id, fqdn,
                            (dns_type_t)query_type,
                            from, from_len,
                            resp_data, (size_t)resp_data_len);
    }
}

/* Respond to the oldest pending query (lazy mode) */
static void lazy_respond(tunnel_server_t *ts, server_session_t *sess,
                          const uint8_t *pkt_buf, size_t pkt_len)
{
    pending_query_t *pq = lazy_dequeue(sess);
    if (!pq) {
        return;
    }

    send_tunnel_response(ts, sess,
                          pq->query_id, pq->question_fqdn,
                          pq->query_type,
                          (const struct sockaddr *)&pq->client_addr,
                          pq->client_addr_len,
                          pkt_buf, pkt_len);
    lazy_consume(sess, pq);
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
    int               is_syn  = 0;
    int               has_data = 0; /* did this query carry tunnel data? */

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

            has_data = 1;

            e = transport_parse_packet(decoded, (size_t)dec_len,
                                        &hdr, &payload, &payload_len);
            if (e == ERR_OK) {
                /* SYN: create session */
                if ((hdr.flags & TUNNEL_FLAG_SYN) && !sess) {
                    sess = alloc_session(ts, session_id);
                    if (sess) {
                        memcpy(&sess->client_addr, from, from_len);
                        sess->client_addr_len = from_len;

                        /* Channel negotiation: client sends its CHAN_* bitmask
                         * in SYN payload bytes [0..3].  Server intersects with
                         * its own supported channels. */
                        if (payload_len >= 4) {
                            uint32_t client_chans =
                                ((uint32_t)payload[0] << 24) |
                                ((uint32_t)payload[1] << 16) |
                                ((uint32_t)payload[2] <<  8) |
                                 (uint32_t)payload[3];
                            sess->transport.active_channels =
                                client_chans & ts->cfg.active_channels;
                        } else {
                            /* No channel info in SYN: use server defaults */
                            sess->transport.active_channels =
                                ts->cfg.active_channels;
                        }

                        LOG_INFO("New session 0x%04x from client (channels=0x%08x)",
                                 session_id,
                                 (unsigned)sess->transport.active_channels);
                        is_syn = 1;
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

    pkt_len = -1;
    /* SYN-ACK: include negotiated channels bitmask (4 bytes) as payload.
     * SYN-ACK is always responded immediately (never lazy). */
    if (is_syn) {
        uint8_t syn_ack_payload[4];
        uint32_t neg = sess->transport.active_channels;
        syn_ack_payload[0] = (uint8_t)(neg >> 24);
        syn_ack_payload[1] = (uint8_t)((neg >> 16) & 0xFFU);
        syn_ack_payload[2] = (uint8_t)((neg >>  8) & 0xFFU);
        syn_ack_payload[3] = (uint8_t)(neg & 0xFFU);
        pkt_len = transport_build_packet(&sess->transport, session_id,
                                          TUNNEL_FLAG_SYN | TUNNEL_FLAG_ACK,
                                          syn_ack_payload, 4,
                                          pkt_buf, sizeof(pkt_buf));
        if (pkt_len > 0) {
            send_tunnel_response(ts, sess, query_id, fqdn, (uint16_t)qtype,
                                  from, from_len,
                                  pkt_buf, (size_t)pkt_len);
        }
        return;
    }

    /* DATA/FIN: respond immediately with ACK */
    if (has_data) {
        pkt_len = transport_build_packet(&sess->transport, session_id,
                                          TUNNEL_FLAG_ACK,
                                          NULL, 0, pkt_buf, sizeof(pkt_buf));
        if (pkt_len > 0) {
            /* If lazy mode is on and we have pending queries, respond to the
             * oldest pending query instead of this one.  This is iodine's
             * key innovation: when data arrives, the response goes to the
             * _previously queued_ poll, not the current request. */
            if (ts->cfg.lazy_mode && sess->pending_count > 0) {
                lazy_respond(ts, sess, pkt_buf, (size_t)pkt_len);
                /* Queue this query for the next response */
                lazy_enqueue(sess, query_id, fqdn, (uint16_t)qtype,
                             from, from_len);
            } else {
                send_tunnel_response(ts, sess, query_id, fqdn,
                                      (uint16_t)qtype, from, from_len,
                                      pkt_buf, (size_t)pkt_len);
            }
        }
        return;
    }

    /* POLL: lazy mode — queue the query, respond later when data arrives.
     * If lazy mode is off, respond immediately with an empty ACK. */
    if (ts->cfg.lazy_mode) {
        /* In lazy mode, queue this POLL query. If we already have a
         * pending query waiting, respond to the OLD one now (with
         * an empty ACK) and queue this new one for the next response.
         * This keeps exactly one query pending most of the time. */
        if (sess->pending_count > 0) {
            /* Respond to the oldest pending query with empty ACK */
            pkt_len = transport_build_packet(&sess->transport, session_id,
                                              TUNNEL_FLAG_ACK,
                                              NULL, 0, pkt_buf, sizeof(pkt_buf));
            if (pkt_len > 0) {
                lazy_respond(ts, sess, pkt_buf, (size_t)pkt_len);
            }
        }
        /* Queue this query for later */
        lazy_enqueue(sess, query_id, fqdn, (uint16_t)qtype,
                     from, from_len);
    } else {
        /* Immediate mode: respond right away */
        pkt_len = transport_build_packet(&sess->transport, session_id,
                                          TUNNEL_FLAG_ACK,
                                          NULL, 0, pkt_buf, sizeof(pkt_buf));
        if (pkt_len > 0) {
            send_tunnel_response(ts, sess, query_id, fqdn, (uint16_t)qtype,
                                  from, from_len,
                                  pkt_buf, (size_t)pkt_len);
        }
    }
}

/* ------------------------------------------------------------------ */
/* Lazy mode drain timer (iodine-inspired)                              */
/* ------------------------------------------------------------------ */

static void lazy_timer_cb(uv_timer_t *timer)
{
    tunnel_server_t *ts  = (tunnel_server_t *)timer->data;
    uint64_t         now = get_time_ms();
    size_t           i;
    int              j;

    /* Drain any pending queries that have been waiting too long.
     * This prevents DNS server timeouts (typically 5-10s per RFC 1035).
     * iodine uses a similar approach with a 4-second timeout. */
    for (i = 0; i < MAX_SESSIONS; i++) {
        server_session_t *s = &ts->sessions[i];
        if (s->state == SERVER_SESSION_NEW) {
            continue;
        }
        for (j = 0; j < LAZY_QUEUE_SIZE; j++) {
            pending_query_t *pq = &s->pending[j];
            if (!pq->valid) {
                continue;
            }
            if ((now - pq->received_ms) >= LAZY_TIMEOUT_MS) {
                /* Timeout: respond with empty ACK */
                uint8_t ack_buf[512];
                int     ack_len;

                ack_len = transport_build_packet(&s->transport,
                                                  s->session_id,
                                                  TUNNEL_FLAG_ACK,
                                                  NULL, 0,
                                                  ack_buf, sizeof(ack_buf));
                if (ack_len > 0) {
                    send_tunnel_response(ts, s,
                                          pq->query_id, pq->question_fqdn,
                                          pq->query_type,
                                          (const struct sockaddr *)&pq->client_addr,
                                          pq->client_addr_len,
                                          ack_buf, (size_t)ack_len);
                }
                lazy_consume(s, pq);
            }
        }
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

    /* Start lazy mode drain timer if enabled */
    if (ts->cfg.lazy_mode) {
        uv_timer_init(ts->loop, &ts->lazy_timer);
        ts->lazy_timer.data = ts;
        uv_timer_start(&ts->lazy_timer, lazy_timer_cb,
                       LAZY_DRAIN_INTERVAL_MS, LAZY_DRAIN_INTERVAL_MS);
    }

    return ERR_OK;
}

void tunnel_server_stop(tunnel_server_t *ts)
{
    if (!ts) {
        return;
    }
    uv_timer_stop(&ts->cleanup_timer);
    if (!uv_is_closing((uv_handle_t *)&ts->cleanup_timer)) {
        uv_close((uv_handle_t *)&ts->cleanup_timer, NULL);
    }
    if (ts->cfg.lazy_mode) {
        uv_timer_stop(&ts->lazy_timer);
        if (!uv_is_closing((uv_handle_t *)&ts->lazy_timer)) {
            uv_close((uv_handle_t *)&ts->lazy_timer, NULL);
        }
    }
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
