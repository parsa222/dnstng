#include "smtp_channel.h"
#include "encode.h"
#include "util.h"
#include <string.h>
#include <stdio.h>

/* ------------------------------------------------------------------ */
/* Internal callbacks                                                   */
/* ------------------------------------------------------------------ */

static void smtp_alloc_cb(uv_handle_t *handle, size_t suggested_size,
                           uv_buf_t *buf)
{
    smtp_channel_t *ch = (smtp_channel_t *)handle->data;
    size_t          avail;

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

/* Parse incoming SMTP response lines.
 * Lines of the form "250-{b36data}\r\n" carry downstream data.
 * Line "250 ok\r\n" ends the response. */
static void smtp_process_recv(smtp_channel_t *ch)
{
    char   *start = (char *)ch->recv_buf;
    char   *p;
    char   *line_end;
    size_t  consumed = 0;
    size_t  line_len;
    uint8_t decoded[512];
    int     dlen;

    while (consumed < ch->recv_len) {
        p        = start + consumed;
        line_end = NULL;
        {
            size_t remaining = ch->recv_len - consumed;
            size_t k;
            for (k = 0; k + 1 < remaining; k++) {
                if (p[k] == '\r' && p[k + 1] == '\n') {
                    line_end = p + k;
                    break;
                }
            }
        }
        if (!line_end) {
            break; /* incomplete line */
        }
        line_len = (size_t)(line_end - p);
        consumed += line_len + 2; /* skip \r\n */

        /* Check for "250-" continuation carrying data */
        if (line_len > 4U && p[0] == '2' && p[1] == '5' && p[2] == '0'
                && p[3] == '-') {
            char   *b36_start = p + 4;
            size_t  b36_len   = line_len - 4U;

            dlen = decode_data(b36_start, b36_len, decoded, sizeof(decoded),
                               ENCODE_BASE36);
            if (dlen > 0 && ch->on_recv) {
                ch->on_recv(decoded, (size_t)dlen, ch->userdata);
            }
        }
    }

    /* Compact buffer */
    if (consumed > 0 && consumed <= ch->recv_len) {
        ch->recv_len -= consumed;
        if (ch->recv_len > 0) {
            memmove(ch->recv_buf, ch->recv_buf + consumed, ch->recv_len);
        }
    }
}

static void smtp_read_cb(uv_stream_t *stream, ssize_t nread,
                          const uv_buf_t *buf)
{
    smtp_channel_t *ch = (smtp_channel_t *)stream->data;

    (void)buf;

    if (nread < 0) {
        ch->connected = 0;
        if (ch->on_conn) {
            ch->on_conn(0, ch->userdata);
        }
        return;
    }
    if (nread == 0) {
        return;
    }

    ch->recv_len += (size_t)nread;
    smtp_process_recv(ch);
}

static void smtp_write_cb(uv_write_t *req, int status)
{
    (void)req;
    (void)status;
}

static void smtp_connect_cb(uv_connect_t *req, int status)
{
    smtp_channel_t *ch = (smtp_channel_t *)req->data;

    if (status < 0) {
        ch->connected = 0;
        if (ch->on_conn) {
            ch->on_conn(0, ch->userdata);
        }
        return;
    }

    ch->connected = 1;
    if (ch->on_conn) {
        ch->on_conn(1, ch->userdata);
    }

    uv_read_start((uv_stream_t *)&ch->tcp, smtp_alloc_cb, smtp_read_cb);
}

static void smtp_close_cb(uv_handle_t *h)
{
    (void)h;
}

/* ------------------------------------------------------------------ */
/* Public API                                                           */
/* ------------------------------------------------------------------ */

err_t smtp_channel_init(smtp_channel_t *ch, uv_loop_t *loop,
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
    ch->tcp.data          = ch;
    ch->connect_req.data  = ch;
    return ERR_OK;
}

err_t smtp_channel_connect(smtp_channel_t *ch)
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
                         smtp_connect_cb);
    return (rc == 0) ? ERR_OK : ERR_IO;
}

err_t smtp_channel_send(smtp_channel_t *ch,
                        const uint8_t *data, size_t len)
{
    char     b36[1024];
    int      enc;
    int      n;
    uv_buf_t uvbuf;

    if (!ch || !ch->connected || !data || len == 0) {
        return ERR_INVAL;
    }

    enc = encode_data(data, len, b36, sizeof(b36), ENCODE_BASE36);
    if (enc < 0) {
        return ERR_OVERFLOW;
    }
    b36[enc] = '\0';

    n = snprintf((char *)ch->send_buf, sizeof(ch->send_buf),
                 "EHLO %s.t.%s\r\n", b36, ch->domain);
    if (n < 0 || (size_t)n >= sizeof(ch->send_buf)) {
        return ERR_OVERFLOW;
    }
    ch->send_len = (size_t)n;

    uvbuf = uv_buf_init((char *)ch->send_buf, (unsigned int)ch->send_len);
    uv_write(&ch->write_req, (uv_stream_t *)&ch->tcp, &uvbuf, 1,
             smtp_write_cb);
    return ERR_OK;
}

void smtp_channel_free(smtp_channel_t *ch)
{
    if (!ch) {
        return;
    }
    ch->connected = 0;
    if (!uv_is_closing((uv_handle_t *)&ch->tcp)) {
        uv_close((uv_handle_t *)&ch->tcp, smtp_close_cb);
    }
}
