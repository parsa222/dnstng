#include "dns_server.h"
#include "dns_packet.h"
#include "log.h"
#include <string.h>
#include <stdlib.h>
#include <ctype.h>

#define DNS_UDP_BUF 4096

/* Forward declaration */
static void send_cb(uv_udp_send_t *req, int status);

/* ------------------------------------------------------------------ */
/* Internal helpers                                                     */
/* ------------------------------------------------------------------ */

static void alloc_cb(uv_handle_t *handle, size_t suggested_size,
                     uv_buf_t *buf)
{
    static char udp_buf[DNS_UDP_BUF];
    (void)handle;
    (void)suggested_size;
    buf->base = udp_buf;
    buf->len  = sizeof(udp_buf);
}

static int fqdn_matches_domain(const char *fqdn, const char *domain)
{
    size_t fqdn_len   = strlen(fqdn);
    size_t domain_len = strlen(domain);
    size_t suffix_len = domain_len + 1; /* '.' + domain */

    if (fqdn_len <= domain_len) {
        return 0;
    }

    /* fqdn must end with ".domain" */
    if (fqdn[fqdn_len - suffix_len] != '.') {
        return 0;
    }

    return (strncasecmp(fqdn + fqdn_len - domain_len,
                         domain, domain_len) == 0);
}

/* ------------------------------------------------------------------ */
/* UDP receive callback                                                 */
/* ------------------------------------------------------------------ */

static void recv_cb(uv_udp_t *handle, ssize_t nread, const uv_buf_t *buf,
                     const struct sockaddr *addr, unsigned int flags)
{
    dns_server_t *srv = (dns_server_t *)handle;
    char          fqdn[512];
    uint16_t      query_id;
    uint16_t      qtype;
    uint16_t      qdcount;
    size_t        off;
    int           ret;

    if (nread <= 0 || !addr) {
        return;
    }

    (void)flags;

    {
        const uint8_t *b   = (const uint8_t *)buf->base;
        size_t         len = (size_t)nread;

        if (len < 12) {
            return;
        }

        query_id = (uint16_t)((b[0] << 8) | b[1]);
        qdcount  = (uint16_t)((b[4] << 8) | b[5]);

        if (qdcount == 0) {
            return;
        }

        off = 12;

        /* Decode question QNAME */
        ret = 0;
        {
            size_t  out_pos = 0;
            int     loops   = 0;
            size_t  cur     = off;

            while (cur < len && loops++ < 128) {
                uint8_t c = b[cur];

                if (c == 0) {
                    if (ret == 0) {
                        ret = (int)(cur + 1);
                    }
                    break;
                }

                if ((c & 0xC0U) == 0xC0U) {
                    if (cur + 1 < len) {
                        size_t ptr = (size_t)(((c & 0x3FU) << 8) | b[cur + 1]);
                        if (ret == 0) {
                            ret = (int)(cur + 2);
                        }
                        cur = ptr;
                        continue;
                    }
                    return;
                }

                {
                    uint8_t label_len = c;
                    cur++;
                    if (cur + label_len > len) {
                        return;
                    }
                    if (out_pos > 0) {
                        if (out_pos >= sizeof(fqdn) - 1) {
                            return;
                        }
                        fqdn[out_pos++] = '.';
                    }
                    if (out_pos + label_len >= sizeof(fqdn)) {
                        return;
                    }
                    memcpy(fqdn + out_pos, b + cur, label_len);
                    out_pos += label_len;
                    cur     += label_len;
                }
            }

            fqdn[out_pos] = '\0';
            off = (size_t)ret;
        }

        if (off + 4 > len) {
            return;
        }

        qtype = (uint16_t)((b[off] << 8) | b[off + 1]);
        off  += 4;
    }

    /* Check if this is a query for our tunnel domain */
    if (!fqdn_matches_domain(fqdn, srv->domain)) {
        /* Send NXDOMAIN */
        {
            uv_buf_t ubuf;
            uint8_t *rbuf = (uint8_t *)malloc(12);

            if (!rbuf) {
                LOG_ERROR("dns_server: out of memory for NXDOMAIN response");
                return;
            }

            memcpy(rbuf, buf->base, 2); /* copy ID */
            rbuf[2] = 0x81U; /* QR=1, RD=1 */
            rbuf[3] = 0x83U; /* NXDOMAIN */
            memset(rbuf + 4, 0, 8);

            ubuf.base = (char *)rbuf;
            ubuf.len  = 12;

            {
                uv_udp_send_t *sreq = (uv_udp_send_t *)malloc(sizeof(uv_udp_send_t));
                if (sreq) {
                    int sr;
                    sreq->data = rbuf;
                    sr = uv_udp_send(sreq, handle, &ubuf, 1, addr, send_cb);
                    if (sr < 0) {
                        free(rbuf);
                        free(sreq);
                    }
                } else {
                    free(rbuf);
                }
            }
        }
        return;
    }

    if (srv->on_query) {
        socklen_t from_len;
        if (addr->sa_family == AF_INET) {
            from_len = sizeof(struct sockaddr_in);
        } else {
            from_len = sizeof(struct sockaddr_in6);
        }
        srv->on_query(query_id, fqdn, (dns_type_t)qtype,
                       addr, from_len, srv->userdata);
    }
}

/* ------------------------------------------------------------------ */
/* Send callback (frees allocated buffer)                              */
/* ------------------------------------------------------------------ */

static void send_cb(uv_udp_send_t *req, int status)
{
    if (status < 0) {
        LOG_WARN("dns_server send error: %s", uv_strerror(status));
    }
    free(req->data);
    free(req);
}

/* ------------------------------------------------------------------ */
/* Public API                                                           */
/* ------------------------------------------------------------------ */

err_t dns_server_init(dns_server_t *srv, uv_loop_t *loop,
                       const char *bind_addr, uint16_t port,
                       const char *domain)
{
    struct sockaddr_in addr;
    int                r;

    if (!srv || !loop || !bind_addr || !domain) {
        return ERR_INVAL;
    }

    memset(srv, 0, sizeof(*srv));
    srv->loop = loop;
    strncpy(srv->domain, domain, sizeof(srv->domain) - 1);
    srv->domain[sizeof(srv->domain) - 1] = '\0';

    r = uv_udp_init(loop, &srv->udp);
    if (r < 0) {
        return ERR_IO;
    }

    r = uv_ip4_addr(bind_addr, port, &addr);
    if (r < 0) {
        return ERR_INVAL;
    }

    r = uv_udp_bind(&srv->udp, (const struct sockaddr *)&addr,
                     UV_UDP_REUSEADDR);
    if (r < 0) {
        return ERR_IO;
    }

    return ERR_OK;
}

err_t dns_server_start(dns_server_t *srv)
{
    int r;

    if (!srv) {
        return ERR_INVAL;
    }

    r = uv_udp_recv_start(&srv->udp, alloc_cb, recv_cb);
    if (r < 0) {
        return ERR_IO;
    }

    return ERR_OK;
}

static void udp_close_cb(uv_handle_t *handle)
{
    (void)handle;
}

void dns_server_stop(dns_server_t *srv)
{
    if (!srv) {
        return;
    }
    uv_udp_recv_stop(&srv->udp);
    if (!uv_is_closing((uv_handle_t *)&srv->udp)) {
        uv_close((uv_handle_t *)&srv->udp, udp_close_cb);
    }
}

err_t dns_server_respond(dns_server_t *srv, uint16_t query_id,
                          const char *fqdn, dns_type_t qtype,
                          const struct sockaddr *to, socklen_t to_len,
                          const uint8_t *data, size_t data_len)
{
    uint8_t       *rbuf;
    size_t         rbuf_cap = 512 + data_len;
    int            rlen;
    dns_answer_t   ans;
    uv_udp_send_t *sreq;
    uv_buf_t       ubuf;

    (void)to_len;

    if (!srv || !to) {
        return ERR_INVAL;
    }

    rbuf = (uint8_t *)malloc(rbuf_cap);
    if (!rbuf) {
        return ERR_NOMEM;
    }

    memset(&ans, 0, sizeof(ans));
    ans.type      = DNS_TYPE_TXT;
    ans.rdata     = data;
    ans.rdata_len = data_len;
    ans.ttl       = 0;

    rlen = dns_build_response(query_id, fqdn, qtype, &ans, 1,
                               rbuf, rbuf_cap);
    if (rlen < 0) {
        free(rbuf);
        return ERR_OVERFLOW;
    }

    sreq = (uv_udp_send_t *)malloc(sizeof(uv_udp_send_t));
    if (!sreq) {
        free(rbuf);
        return ERR_NOMEM;
    }

    sreq->data = rbuf;
    ubuf.base  = (char *)rbuf;
    ubuf.len   = (size_t)rlen;

    {
        int sr = uv_udp_send(sreq, &srv->udp, &ubuf, 1, to, send_cb);
        if (sr < 0) {
            free(rbuf);
            free(sreq);
            return ERR_IO;
        }
    }

    return ERR_OK;
}

/* ------------------------------------------------------------------ */
/* Send a pre-built DNS packet                                          */
/* ------------------------------------------------------------------ */

err_t dns_server_send_raw(dns_server_t *srv, const uint8_t *buf, size_t len,
                           const struct sockaddr *to, socklen_t to_len)
{
    uint8_t       *rbuf;
    uv_udp_send_t *sreq;
    uv_buf_t       ubuf;

    (void)to_len;

    if (!srv || !buf || len == 0 || !to) {
        return ERR_INVAL;
    }

    rbuf = (uint8_t *)malloc(len);
    if (!rbuf) {
        return ERR_NOMEM;
    }
    memcpy(rbuf, buf, len);

    sreq = (uv_udp_send_t *)malloc(sizeof(uv_udp_send_t));
    if (!sreq) {
        free(rbuf);
        return ERR_NOMEM;
    }

    sreq->data = rbuf;
    ubuf.base  = (char *)rbuf;
    ubuf.len   = len;

    {
        int sr = uv_udp_send(sreq, &srv->udp, &ubuf, 1, to, send_cb);
        if (sr < 0) {
            free(rbuf);
            free(sreq);
            return ERR_IO;
        }
    }

    return ERR_OK;
}
