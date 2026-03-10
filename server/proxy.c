#include "proxy.h"
#include "log.h"
#include <stdlib.h>
#include <string.h>
#include <netdb.h>
#include <arpa/inet.h>

/* ------------------------------------------------------------------ */
/* Write request helper                                                 */
/* ------------------------------------------------------------------ */

typedef struct {
    uv_write_t req;
    uint8_t   *buf;
} write_req_t;

static void write_done_cb(uv_write_t *req, int status)
{
    write_req_t *wr = (write_req_t *)req;

    if (status < 0) {
        LOG_WARN("proxy write error: %s", uv_strerror(status));
    }
    free(wr->buf);
    free(wr);
}

/* ------------------------------------------------------------------ */
/* TCP connection lifetime                                              */
/* ------------------------------------------------------------------ */

static void alloc_cb(uv_handle_t *handle, size_t suggested_size,
                      uv_buf_t *buf)
{
    (void)handle;
    buf->base = (char *)malloc(suggested_size);
    if (!buf->base) {
        LOG_WARN("proxy alloc_cb: malloc(%zu) failed", suggested_size);
        buf->len = 0;
    } else {
        buf->len = suggested_size;
    }
}

static void read_cb(uv_stream_t *stream, ssize_t nread, const uv_buf_t *buf)
{
    proxy_conn_t *conn = (proxy_conn_t *)stream;

    if (nread > 0) {
        if (conn->on_data) {
            conn->on_data(conn->stream_id, (uint8_t *)buf->base,
                           (size_t)nread, conn->userdata);
        }
    } else if (nread < 0) {
        if (conn->on_close) {
            conn->on_close(conn->stream_id, conn->userdata);
        }
    }

    if (buf->base) {
        free(buf->base);
    }
}

static void tcp_close_cb(uv_handle_t *handle)
{
    free(handle); /* proxy_conn_t allocated with malloc */
}

static void connect_cb(uv_connect_t *req, int status)
{
    proxy_conn_t *conn = (proxy_conn_t *)req->handle;

    if (status < 0) {
        LOG_WARN("proxy connect failed: %s", uv_strerror(status));
        if (conn->on_close) {
            conn->on_close(conn->stream_id, conn->userdata);
        }
        uv_close((uv_handle_t *)&conn->tcp, tcp_close_cb);
        return;
    }

    uv_read_start((uv_stream_t *)&conn->tcp, alloc_cb, read_cb);
}

/* ------------------------------------------------------------------ */
/* Public API                                                           */
/* ------------------------------------------------------------------ */

err_t proxy_init(proxy_t *proxy, uv_loop_t *loop)
{
    if (!proxy || !loop) {
        return ERR_INVAL;
    }
    memset(proxy, 0, sizeof(*proxy));
    proxy->loop = loop;
    return ERR_OK;
}

err_t proxy_connect(proxy_t *proxy, uint16_t stream_id,
                     const char *host, uint16_t port)
{
    proxy_conn_t       *conn;
    struct addrinfo     hints;
    struct addrinfo    *res = NULL;
    char                portstr[8];
    int                 r;
    struct sockaddr_in  addr4;

    if (!proxy || !host) {
        return ERR_INVAL;
    }

    conn = (proxy_conn_t *)malloc(sizeof(proxy_conn_t));
    if (!conn) {
        return ERR_NOMEM;
    }
    memset(conn, 0, sizeof(*conn));
    conn->stream_id = stream_id;
    conn->on_data   = proxy->on_data;
    conn->on_close  = proxy->on_close;
    conn->userdata  = proxy->userdata;

    uv_tcp_init(proxy->loop, &conn->tcp);

    /* Resolve host synchronously (simplification for proxy side) */
    memset(&hints, 0, sizeof(hints));
    hints.ai_family   = AF_INET;
    hints.ai_socktype = SOCK_STREAM;

    snprintf(portstr, sizeof(portstr), "%u", port);
    r = getaddrinfo(host, portstr, &hints, &res);
    if (r != 0 || !res) {
        LOG_WARN("proxy: getaddrinfo(%s) failed: %s",
                 host, (r != 0) ? gai_strerror(r) : "no result");
        uv_close((uv_handle_t *)&conn->tcp, tcp_close_cb);
        return ERR_NOTFOUND;
    }

    memcpy(&addr4, res->ai_addr, sizeof(addr4));
    freeaddrinfo(res);

    r = uv_tcp_connect(&conn->connect_req, &conn->tcp,
                        (const struct sockaddr *)&addr4, connect_cb);
    if (r < 0) {
        uv_close((uv_handle_t *)&conn->tcp, tcp_close_cb);
        return ERR_IO;
    }

    /* Prepend to list */
    conn->next        = proxy->connections;
    proxy->connections = conn;

    return ERR_OK;
}

err_t proxy_send(proxy_t *proxy, uint16_t stream_id,
                  const uint8_t *data, size_t len)
{
    proxy_conn_t *conn;
    write_req_t  *wr;
    uv_buf_t      buf;

    if (!proxy || !data || len == 0) {
        return ERR_INVAL;
    }

    /* Find connection */
    for (conn = proxy->connections; conn; conn = conn->next) {
        if (conn->stream_id == stream_id) {
            break;
        }
    }
    if (!conn) {
        return ERR_NOTFOUND;
    }

    wr = (write_req_t *)malloc(sizeof(write_req_t));
    if (!wr) {
        return ERR_NOMEM;
    }

    wr->buf = (uint8_t *)malloc(len);
    if (!wr->buf) {
        free(wr);
        return ERR_NOMEM;
    }

    memcpy(wr->buf, data, len);
    buf = uv_buf_init((char *)wr->buf, (unsigned int)len);

    {
        int r = uv_write(&wr->req, (uv_stream_t *)&conn->tcp, &buf, 1,
                          write_done_cb);
        if (r < 0) {
            LOG_WARN("proxy_send: uv_write failed: %s", uv_strerror(r));
            free(wr->buf);
            free(wr);
            return ERR_IO;
        }
    }
    return ERR_OK;
}

void proxy_close(proxy_t *proxy, uint16_t stream_id)
{
    proxy_conn_t  *conn;
    proxy_conn_t **prev;

    if (!proxy) {
        return;
    }

    prev = &proxy->connections;
    for (conn = proxy->connections; conn; conn = conn->next) {
        if (conn->stream_id == stream_id) {
            *prev = conn->next;
            uv_read_stop((uv_stream_t *)&conn->tcp);
            uv_close((uv_handle_t *)&conn->tcp, tcp_close_cb);
            return;
        }
        prev = &conn->next;
    }
}

void proxy_free(proxy_t *proxy)
{
    proxy_conn_t *conn;
    proxy_conn_t *next;

    if (!proxy) {
        return;
    }

    conn = proxy->connections;
    while (conn) {
        next = conn->next;
        uv_read_stop((uv_stream_t *)&conn->tcp);
        if (!uv_is_closing((uv_handle_t *)&conn->tcp)) {
            uv_close((uv_handle_t *)&conn->tcp, tcp_close_cb);
        }
        conn = next;
    }
    proxy->connections = NULL;
}
