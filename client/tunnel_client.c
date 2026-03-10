#include "tunnel_client.h"
#include "socks5.h"
#include "encode.h"
#include "log.h"
#include "stealth.h"
#include "channel.h"
#include "chain.h"
#include <arpa/nameser.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <arpa/inet.h>

/* ------------------------------------------------------------------ */
/* Forward declarations                                                 */
/* ------------------------------------------------------------------ */

static void poll_timer_cb(uv_timer_t *timer);
static void retransmit_timer_cb(uv_timer_t *timer);
static void send_dns_query(tunnel_client_t *tc, const uint8_t *pkt,
                            size_t pkt_len, uint16_t stream_id);
static void on_socks5_connect(socks5_conn_t *conn, const char *host,
                               uint16_t port, void *userdata);
static void on_socks5_data(socks5_conn_t *conn, const uint8_t *data,
                            size_t len, void *userdata);
static void on_socks5_close(socks5_conn_t *conn, void *userdata);

/* ------------------------------------------------------------------ */
/* Stream helpers                                                       */
/* ------------------------------------------------------------------ */

static stream_t *find_stream(tunnel_client_t *tc, uint16_t stream_id)
{
    int i;
    for (i = 0; i < MAX_STREAMS; i++) {
        if (tc->streams[i].active && tc->streams[i].stream_id == stream_id) {
            return &tc->streams[i];
        }
    }
    return NULL;
}

static stream_t *alloc_stream(tunnel_client_t *tc)
{
    int i;
    for (i = 0; i < MAX_STREAMS; i++) {
        if (!tc->streams[i].active) {
            memset(&tc->streams[i], 0, sizeof(tc->streams[i]));
            tc->streams[i].active    = 1;
            tc->streams[i].stream_id = (uint16_t)i;
            return &tc->streams[i];
        }
    }
    return NULL;
}

static void free_stream(stream_t *st)
{
    st->active  = 0;
    st->socks5  = NULL;
}

/* ------------------------------------------------------------------ */
/* DNS query / response                                                 */
/* ------------------------------------------------------------------ */

/* Build the FQDN: {encoded_data}.{session_hex}.t.{domain}
 * or for a POLL: poll.{session_hex}.t.{domain} */
static int build_query_fqdn(tunnel_client_t *tc,
                              const uint8_t *payload, size_t payload_len,
                              char *fqdn, size_t fqdn_cap)
{
    char   labels[512];
    int    llen;
    int    written;

    if (payload && payload_len > 0) {
        llen = encode_to_labels(payload, payload_len, labels,
                                 sizeof(labels), tc->cfg.encode_mode);
        if (llen < 0) {
            return -1;
        }
        written = snprintf(fqdn, fqdn_cap, "%s.%04x.t.%s",
                           labels, tc->session_id, tc->cfg.domain);
    } else {
        written = snprintf(fqdn, fqdn_cap, "poll.%04x.t.%s",
                           tc->session_id, tc->cfg.domain);
    }

    return (written > 0 && (size_t)written < fqdn_cap) ? written : -1;
}

/* c-ares TXT query callback */
typedef struct {
    tunnel_client_t *tc;
    uint16_t         stream_id;
} query_ctx_t;

static void ares_txt_cb(void *arg, int status, int timeouts,
                         unsigned char *abuf, int alen)
{
    query_ctx_t *qctx  = (query_ctx_t *)arg;
    tunnel_client_t *tc = qctx->tc;
    stream_t        *st;

    (void)timeouts;

    free(qctx);

    if (status != ARES_SUCCESS || !abuf || alen <= 0) {
        return;
    }

    /* ── Multi-channel unpack path ─────────────────────────────────── */
    {
        dns_parsed_response_t parsed;
        err_t e;

        e = dns_parse_response_full(abuf, (size_t)alen, &parsed);
        if (e == ERR_OK) {
            uint8_t flat[4096];
            int     flat_len = -1;

            /* Try CNAME chain parsing first */
            if (tc->transport.active_channels & CHAN_CNAME_CHAIN) {
                flat_len = chain_parse_cname(&parsed, tc->cfg.domain,
                                              flat, sizeof(flat));
            }
            /* Try NS referral chain parsing */
            if (flat_len <= 0 &&
                    (tc->transport.active_channels & CHAN_NS_CHAIN)) {
                flat_len = chain_parse_ns_referral(&parsed, tc->cfg.domain,
                                                    flat, sizeof(flat));
            }
            /* Standard multi-channel unpack */
            if (flat_len <= 0 && tc->transport.active_channels != 0) {
                flat_len = channel_unpack(&parsed,
                                           tc->transport.active_channels,
                                           flat, sizeof(flat));
            }

            if (flat_len > 0) {
                tunnel_header_t  hdr;
                const uint8_t   *payload;
                size_t           payload_len;

                e = transport_parse_packet(flat, (size_t)flat_len,
                                            &hdr, &payload, &payload_len);
                if (e == ERR_OK) {
                    transport_ack(&tc->transport, hdr.seq_num);

                    /* SYN-ACK: extract negotiated channel bitmask */
                    if ((hdr.flags & (TUNNEL_FLAG_SYN | TUNNEL_FLAG_ACK)) ==
                            (TUNNEL_FLAG_SYN | TUNNEL_FLAG_ACK)) {
                        if (payload_len >= 4) {
                            uint32_t neg =
                                ((uint32_t)payload[0] << 24) |
                                ((uint32_t)payload[1] << 16) |
                                ((uint32_t)payload[2] <<  8) |
                                 (uint32_t)payload[3];
                            tc->transport.active_channels = neg;
                            LOG_INFO("Negotiated channels: 0x%08x",
                                     (unsigned)neg);
                        }
                        tc->state = SESSION_ACTIVE;
                        return;
                    }

                    if ((hdr.flags & TUNNEL_FLAG_DATA) && payload_len > 0) {
                        st = find_stream(tc, hdr.session_id);
                        if (!st) {
                            st = find_stream(tc, tc->session_id);
                        }
                        if (st && st->socks5) {
                            socks5_conn_send(st->socks5, payload,
                                             payload_len);
                        }
                    }

                    if (hdr.flags & TUNNEL_FLAG_FIN) {
                        st = find_stream(tc, hdr.session_id);
                        if (st && st->socks5) {
                            socks5_conn_close(st->socks5);
                        }
                    }

                    if (hdr.flags & TUNNEL_FLAG_ACK) {
                        transport_ack(&tc->transport, hdr.ack_num);
                    }
                }
                return;
            }
        }
    }

    /* ── Fallback: legacy TXT/NULL parsing ─────────────────────────── */
    {
        const uint8_t *buf = abuf;
        size_t         len = (size_t)alen;
        uint16_t       ancount;
        size_t         off = 12;
        uint16_t       i;

        if (len < 12) {
            return;
        }

        /* Skip questions */
        {
            uint16_t qdcount = (uint16_t)((buf[4] << 8) | buf[5]);
            for (i = 0; i < qdcount; i++) {
                while (off < len) {
                    uint8_t b = buf[off];
                    if (b == 0) { off++; break; }
                    if ((b & 0xC0U) == 0xC0U) { off += 2; break; }
                    off += 1 + b;
                }
                off += 4;
            }
        }

        ancount = (uint16_t)((buf[6] << 8) | buf[7]);
        for (i = 0; i < ancount; i++) {
            uint16_t rtype;
            uint16_t rdlen;

            /* Skip name */
            {
                int nr = 0;
                while (off < len && nr < 128) {
                    uint8_t b = buf[off];
                    if (b == 0) { off++; break; }
                    if ((b & 0xC0U) == 0xC0U) { off += 2; break; }
                    off += 1 + b;
                    nr++;
                }
            }

            if (off + 10 > len) {
                break;
            }

            rtype = (uint16_t)((buf[off] << 8) | buf[off + 1]);
            off  += 2; /* type */
            off  += 2; /* class */
            off  += 4; /* ttl */
            rdlen = (uint16_t)((buf[off] << 8) | buf[off + 1]);
            off  += 2;

            if (off + rdlen > len) {
                break;
            }

            /* TXT or NULL record: extract data */
            if ((rtype == 16 || rtype == 10) && rdlen > 0) {
                const uint8_t *rdata    = buf + off;
                size_t         data_off = 0;

                if (rtype == 16) {
                    if (rdlen < 1) {
                        off += rdlen;
                        continue;
                    }
                    data_off = 1;
                }

                if (rdlen > data_off) {
                    uint8_t decoded[512];
                    int     dec_len;

                    dec_len = decode_from_labels(
                        (const char *)(rdata + data_off),
                        rdlen - data_off,
                        decoded, sizeof(decoded),
                        tc->cfg.encode_mode);

                    if (dec_len > 0) {
                        tunnel_header_t hdr;
                        const uint8_t  *payload;
                        size_t          payload_len;
                        err_t           e;

                        e = transport_parse_packet(decoded, (size_t)dec_len,
                                                    &hdr, &payload,
                                                    &payload_len);
                        if (e == ERR_OK) {
                            transport_ack(&tc->transport, hdr.seq_num);

                            /* SYN-ACK: negotiation in fallback path */
                            if ((hdr.flags & (TUNNEL_FLAG_SYN | TUNNEL_FLAG_ACK)) ==
                                    (TUNNEL_FLAG_SYN | TUNNEL_FLAG_ACK)) {
                                if (payload_len >= 4) {
                                    uint32_t neg =
                                        ((uint32_t)payload[0] << 24) |
                                        ((uint32_t)payload[1] << 16) |
                                        ((uint32_t)payload[2] <<  8) |
                                         (uint32_t)payload[3];
                                    tc->transport.active_channels = neg;
                                }
                                tc->state = SESSION_ACTIVE;
                                off += rdlen;
                                continue;
                            }

                            if ((hdr.flags & TUNNEL_FLAG_DATA) && payload_len > 0) {
                                st = find_stream(tc, hdr.session_id);
                                if (!st) {
                                    st = find_stream(tc, tc->session_id);
                                }
                                if (st && st->socks5) {
                                    socks5_conn_send(st->socks5, payload,
                                                     payload_len);
                                }
                            }

                            if (hdr.flags & TUNNEL_FLAG_FIN) {
                                st = find_stream(tc, hdr.session_id);
                                if (st && st->socks5) {
                                    socks5_conn_close(st->socks5);
                                }
                            }

                            if (hdr.flags & TUNNEL_FLAG_ACK) {
                                transport_ack(&tc->transport, hdr.ack_num);
                            }
                        }
                    }
                }
            }

            off += rdlen;
        }
    }
}

static void send_dns_query(tunnel_client_t *tc, const uint8_t *pkt,
                            size_t pkt_len, uint16_t stream_id)
{
    char         fqdn[768];
    query_ctx_t *qctx;

    (void)stream_id;

    if (build_query_fqdn(tc, pkt, pkt_len, fqdn, sizeof(fqdn)) < 0) {
        LOG_WARN("tunnel_client: failed to build FQDN");
        return;
    }

    qctx = (query_ctx_t *)malloc(sizeof(query_ctx_t));
    if (!qctx) {
        return;
    }
    qctx->tc        = tc;
    qctx->stream_id = stream_id;

    ares_query(tc->ares, fqdn, C_IN, T_TXT,
               ares_txt_cb, qctx);
}

/* ------------------------------------------------------------------ */
/* Timers                                                               */
/* ------------------------------------------------------------------ */

static void retransmit_cb_fn(const uint8_t *pkt, size_t len, void *ud)
{
    tunnel_client_t *tc = (tunnel_client_t *)ud;
    send_dns_query(tc, pkt, len, 0);
}

static void retransmit_timer_cb(uv_timer_t *timer)
{
    tunnel_client_t *tc = (tunnel_client_t *)timer->data;
    transport_check_retransmit(&tc->transport, get_time_ms(), 1000,
                                retransmit_cb_fn, tc);
}

static void poll_timer_cb(uv_timer_t *timer)
{
    tunnel_client_t *tc = (tunnel_client_t *)timer->data;
    int              i;
    int              sent = 0;

    /* Process ares pending */
    ares_process_fd(tc->ares, ARES_SOCKET_BAD, ARES_SOCKET_BAD);

    /* Handshake: send SYN if not yet active */
    if (tc->state == SESSION_INIT || tc->state == SESSION_HANDSHAKE) {
        uint8_t pkt[TUNNEL_HEADER_SIZE + TUNNEL_MAX_PAYLOAD];
        int     pkt_len;
        /* Include channel bitmask in SYN payload (4 bytes big-endian) */
        uint8_t syn_payload[4];
        uint32_t chans = tc->cfg.active_channels;
        syn_payload[0] = (uint8_t)(chans >> 24);
        syn_payload[1] = (uint8_t)((chans >> 16) & 0xFFU);
        syn_payload[2] = (uint8_t)((chans >>  8) & 0xFFU);
        syn_payload[3] = (uint8_t)(chans & 0xFFU);

        pkt_len = transport_build_packet(&tc->transport, tc->session_id,
                                          TUNNEL_FLAG_SYN,
                                          syn_payload, 4, pkt, sizeof(pkt));
        if (pkt_len > 0) {
            send_dns_query(tc, pkt, (size_t)pkt_len, 0);
        }
        tc->state = SESSION_HANDSHAKE;
        return;
    }

    /* Send pending stream data */
    for (i = 0; i < MAX_STREAMS && sent < 4; i++) {
        stream_t *st = &tc->streams[i];
        if (!st->active || st->send_len == 0) {
            continue;
        }

        {
            size_t  chunk = st->send_len;
            uint8_t pkt[TUNNEL_HEADER_SIZE + TUNNEL_MAX_PAYLOAD];
            int     pkt_len;

            if (chunk > TUNNEL_MAX_PAYLOAD) {
                chunk = TUNNEL_MAX_PAYLOAD;
            }

            pkt_len = transport_build_packet(&tc->transport, tc->session_id,
                                              TUNNEL_FLAG_DATA | TUNNEL_FLAG_ACK,
                                              st->send_buf, chunk,
                                              pkt, sizeof(pkt));
            if (pkt_len > 0) {
                send_dns_query(tc, pkt, (size_t)pkt_len,
                               st->stream_id);
                st->send_len -= chunk;
                if (st->send_len > 0) {
                    memmove(st->send_buf, st->send_buf + chunk, st->send_len);
                }
                sent++;
            }
        }
    }

    /* Send POLL if nothing else to send */
    if (sent == 0) {
        uint8_t pkt[TUNNEL_HEADER_SIZE];
        int     pkt_len;

        pkt_len = transport_build_packet(&tc->transport, tc->session_id,
                                          TUNNEL_FLAG_POLL | TUNNEL_FLAG_ACK,
                                          NULL, 0, pkt, sizeof(pkt));
        if (pkt_len > 0) {
            send_dns_query(tc, pkt, (size_t)pkt_len, 0);
        }
    }
}

/* ------------------------------------------------------------------ */
/* SOCKS5 callbacks                                                     */
/* ------------------------------------------------------------------ */

typedef struct {
    tunnel_client_t *tc;
    stream_t        *st;
} socks5_ud_t;

static void on_socks5_connect(socks5_conn_t *conn, const char *host,
                               uint16_t port, void *userdata)
{
    /* At connect time, userdata is still tc (from srv->userdata).
     * We allocate a per-stream ud and update conn->userdata for future
     * data/close callbacks. */
    tunnel_client_t *tc = (tunnel_client_t *)userdata;
    stream_t        *st;
    socks5_ud_t     *ud;
    uint8_t          payload[256];
    size_t           plen;
    size_t           hlen;
    uint8_t          pkt[TUNNEL_HEADER_SIZE + TUNNEL_MAX_PAYLOAD];
    int              pkt_len;

    st = alloc_stream(tc);
    if (!st) {
        socks5_conn_close(conn);
        return;
    }

    ud = (socks5_ud_t *)malloc(sizeof(socks5_ud_t));
    if (!ud) {
        free_stream(st);
        socks5_conn_close(conn);
        return;
    }
    ud->tc = tc;
    ud->st = st;

    st->socks5         = conn;
    conn->userdata     = ud; /* update for future data/close callbacks */

    /* Encode connect request: [2-byte port BE][host string] */
    hlen  = strlen(host);
    if (hlen > 253) {
        hlen = 253;
    }
    plen     = 2 + hlen;
    payload[0] = (uint8_t)(port >> 8);
    payload[1] = (uint8_t)(port & 0xFFU);
    memcpy(payload + 2, host, hlen);

    pkt_len = transport_build_packet(&tc->transport, tc->session_id,
                                      TUNNEL_FLAG_SYN | TUNNEL_FLAG_DATA,
                                      payload, plen, pkt, sizeof(pkt));
    if (pkt_len > 0) {
        send_dns_query(tc, pkt, (size_t)pkt_len, st->stream_id);
    }

    /* Change session to active */
    tc->state = SESSION_ACTIVE;
}

static void on_socks5_data(socks5_conn_t *conn, const uint8_t *data,
                            size_t len, void *userdata)
{
    socks5_ud_t     *ud = (socks5_ud_t *)userdata;
    tunnel_client_t *tc = ud->tc;
    stream_t        *st = ud->st;
    size_t           avail;

    (void)conn;

    avail = sizeof(st->send_buf) - st->send_len;
    if (len > avail) {
        len = avail;
    }
    if (len > 0) {
        memcpy(st->send_buf + st->send_len, data, len);
        st->send_len += len;
    }
    (void)tc;
}

static void on_socks5_close(socks5_conn_t *conn, void *userdata)
{
    socks5_ud_t     *ud = (socks5_ud_t *)userdata;
    tunnel_client_t *tc = ud->tc;
    stream_t        *st = ud->st;
    uint8_t          pkt[TUNNEL_HEADER_SIZE];
    int              pkt_len;

    (void)conn;

    /* Send FIN */
    pkt_len = transport_build_packet(&tc->transport, tc->session_id,
                                      TUNNEL_FLAG_FIN,
                                      NULL, 0, pkt, sizeof(pkt));
    if (pkt_len > 0) {
        send_dns_query(tc, pkt, (size_t)pkt_len, st->stream_id);
    }

    free(ud);
    free_stream(st);
}

/* ------------------------------------------------------------------ */
/* Public API                                                           */
/* ------------------------------------------------------------------ */

err_t tunnel_client_init(tunnel_client_t *tc, uv_loop_t *loop,
                          const client_config_t *cfg)
{
    struct ares_options opts;
    int                 optmask = 0;
    int                 r;

    if (!tc || !loop || !cfg) {
        return ERR_INVAL;
    }

    memset(tc, 0, sizeof(*tc));
    tc->loop = loop;
    tc->cfg  = *cfg;
    tc->state = SESSION_INIT;

    /* Random session_id */
    {
        uint16_t sid;
        stealth_random_bytes((uint8_t *)&sid, sizeof(sid));
        tc->session_id = sid;
    }

    transport_init(&tc->transport);

    /* Init c-ares */
    memset(&opts, 0, sizeof(opts));
    r = ares_init_options(&tc->ares, &opts, optmask);
    if (r != ARES_SUCCESS) {
        return ERR_IO;
    }

    /* Set resolver */
    {
        struct ares_addr_node servers;
        memset(&servers, 0, sizeof(servers));
        servers.family = AF_INET;
        if (inet_pton(AF_INET, cfg->resolver,
                      &servers.addr.addr4) == 1) {
            ares_set_servers(tc->ares, &servers);
        }
    }

    return ERR_OK;
}

err_t tunnel_client_start(tunnel_client_t *tc)
{
    if (!tc) {
        return ERR_INVAL;
    }

    uv_timer_init(tc->loop, &tc->poll_timer);
    tc->poll_timer.data = tc;
    uv_timer_start(&tc->poll_timer, poll_timer_cb,
                   0, (uint64_t)POLL_INTERVAL_MS);

    uv_timer_init(tc->loop, &tc->retransmit_timer);
    tc->retransmit_timer.data = tc;
    uv_timer_start(&tc->retransmit_timer, retransmit_timer_cb, 500, 500);

    return ERR_OK;
}

void tunnel_client_stop(tunnel_client_t *tc)
{
    if (!tc) {
        return;
    }
    uv_timer_stop(&tc->poll_timer);
    if (!uv_is_closing((uv_handle_t *)&tc->poll_timer)) {
        uv_close((uv_handle_t *)&tc->poll_timer, NULL);
    }
    uv_timer_stop(&tc->retransmit_timer);
    if (!uv_is_closing((uv_handle_t *)&tc->retransmit_timer)) {
        uv_close((uv_handle_t *)&tc->retransmit_timer, NULL);
    }
}

err_t tunnel_client_send(tunnel_client_t *tc, uint16_t stream_id,
                          const uint8_t *data, size_t len)
{
    stream_t *st;
    size_t    avail;

    if (!tc || !data || len == 0) {
        return ERR_INVAL;
    }

    st = find_stream(tc, stream_id);
    if (!st) {
        return ERR_NOTFOUND;
    }

    avail = sizeof(st->send_buf) - st->send_len;
    if (len > avail) {
        return ERR_OVERFLOW;
    }

    memcpy(st->send_buf + st->send_len, data, len);
    st->send_len += len;
    return ERR_OK;
}

void tunnel_client_free(tunnel_client_t *tc)
{
    if (!tc) {
        return;
    }
    if (tc->ares) {
        ares_destroy(tc->ares);
        tc->ares = NULL;
    }
    transport_free(&tc->transport);
}

/* ------------------------------------------------------------------ */
/* Called by main.c to wire SOCKS5 server to tunnel client             */
/* ------------------------------------------------------------------ */

void tunnel_client_setup_socks5(tunnel_client_t *tc, socks5_server_t *srv)
{
    srv->on_connect = on_socks5_connect;
    srv->on_data    = on_socks5_data;
    srv->on_close   = on_socks5_close;
    /* srv->userdata = tc so on_socks5_connect receives tc.
     * After connect, conn->userdata is updated to a per-stream socks5_ud_t. */
    srv->userdata = tc;
}
