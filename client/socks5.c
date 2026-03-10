#include "socks5.h"
#include "log.h"
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>

/* ------------------------------------------------------------------ */
/* Internal helpers                                                     */
/* ------------------------------------------------------------------ */

static void alloc_cb(uv_handle_t *handle, size_t suggested_size,
                     uv_buf_t *buf)
{
    socks5_conn_t *conn = (socks5_conn_t *)handle;
    size_t         avail;

    (void)suggested_size;

    avail = SOCKS5_BUF_SIZE - conn->buf_len;
    if (avail == 0) {
        buf->base = NULL;
        buf->len  = 0;
        return;
    }

    buf->base = (char *)(conn->buf + conn->buf_len);
    buf->len  = avail;
}

static void write_cb(uv_write_t *req, int status)
{
    free(req->data); /* free the write buffer */
    free(req);

    if (status < 0) {
        LOG_WARN("socks5 write error: %s", uv_strerror(status));
    }
}

static err_t send_raw(socks5_conn_t *conn, const uint8_t *data, size_t len)
{
    uv_write_t *req;
    uint8_t    *copy;
    uv_buf_t    buf;

    req  = (uv_write_t *)malloc(sizeof(uv_write_t));
    copy = (uint8_t *)malloc(len);
    if (!req || !copy) {
        free(req);
        free(copy);
        return ERR_NOMEM;
    }

    memcpy(copy, data, len);
    req->data = copy;
    buf       = uv_buf_init((char *)copy, (unsigned int)len);

    uv_write(req, (uv_stream_t *)&conn->tcp, &buf, 1, write_cb);
    return ERR_OK;
}

static void do_close_conn(socks5_conn_t *conn);

static void close_handle_cb(uv_handle_t *handle)
{
    socks5_conn_t *conn = (socks5_conn_t *)handle;

    if (conn->on_close) {
        conn->on_close(conn, conn->userdata);
    }
    free(conn);
}

static void do_close_conn(socks5_conn_t *conn)
{
    if (conn->closed) {
        return;
    }
    conn->closed = 1;
    uv_read_stop((uv_stream_t *)&conn->tcp);
    uv_close((uv_handle_t *)&conn->tcp, close_handle_cb);
}

/* ------------------------------------------------------------------ */
/* SOCKS5 state machine                                                 */
/* ------------------------------------------------------------------ */

/* State: S5_STATE_GREETING
 * Expect: VER=5, NMETHODS, METHODS[]
 * Respond: VER=5, METHOD=0 (no auth) */
static void handle_greeting(socks5_conn_t *conn)
{
    uint8_t  resp[2];
    uint8_t  nmethods;

    if (conn->buf_len < 2) {
        return; /* need more data */
    }

    if (conn->buf[0] != 5) {
        LOG_WARN("socks5: bad version %u", conn->buf[0]);
        do_close_conn(conn);
        return;
    }

    nmethods = conn->buf[1];
    if (conn->buf_len < (size_t)(2 + nmethods)) {
        return; /* need more data */
    }

    /* Send method=0 (no auth) */
    resp[0] = 5;
    resp[1] = 0;
    send_raw(conn, resp, 2);

    /* Consume greeting from buffer */
    conn->buf_len -= (size_t)(2 + nmethods);
    if (conn->buf_len > 0) {
        memmove(conn->buf, conn->buf + 2 + nmethods, conn->buf_len);
    }

    conn->state = S5_STATE_REQUEST;
}

/* State: S5_STATE_REQUEST
 * Expect: VER=5, CMD=1, RSV=0, ATYP, ADDR, PORT */
static void handle_request(socks5_conn_t *conn)
{
    uint8_t  atyp;
    size_t   addr_len  = 0;
    size_t   header_sz = 4; /* VER CMD RSV ATYP */
    size_t   total_needed;
    uint16_t port;
    uint8_t  resp[10];
    size_t   consumed;

    if (conn->buf_len < 4) {
        return;
    }

    if (conn->buf[0] != 5 || conn->buf[1] != 1 /* CONNECT */) {
        /* Send failure */
        resp[0] = 5;
        resp[1] = 7; /* command not supported */
        resp[2] = 0;
        resp[3] = 1;
        memset(resp + 4, 0, 6);
        send_raw(conn, resp, 10);
        do_close_conn(conn);
        return;
    }

    atyp = conn->buf[3];

    if (atyp == 1) {
        /* IPv4: 4 bytes + 2 port */
        addr_len     = 4;
        total_needed = header_sz + addr_len + 2;
        if (conn->buf_len < total_needed) {
            return;
        }
        {
            struct in_addr addr;
            memcpy(&addr, conn->buf + 4, 4);
            inet_ntop(AF_INET, &addr, conn->target_host,
                      sizeof(conn->target_host));
        }
        port            = (uint16_t)((conn->buf[4 + addr_len] << 8)
                                     | conn->buf[4 + addr_len + 1]);
        conn->target_port = port;
        consumed = total_needed;

    } else if (atyp == 3) {
        /* Domain: 1 byte length + name + 2 port */
        if (conn->buf_len < 5) {
            return;
        }
        addr_len = conn->buf[4];
        total_needed = header_sz + 1 + addr_len + 2;
        if (conn->buf_len < total_needed) {
            return;
        }
        if (addr_len >= sizeof(conn->target_host)) {
            do_close_conn(conn);
            return;
        }
        memcpy(conn->target_host, conn->buf + 5, addr_len);
        conn->target_host[addr_len] = '\0';
        port = (uint16_t)((conn->buf[5 + addr_len] << 8)
                          | conn->buf[5 + addr_len + 1]);
        conn->target_port = port;
        consumed = total_needed;

    } else if (atyp == 4) {
        /* IPv6: 16 bytes + 2 port */
        addr_len     = 16;
        total_needed = header_sz + addr_len + 2;
        if (conn->buf_len < total_needed) {
            return;
        }
        {
            struct in6_addr addr6;
            memcpy(&addr6, conn->buf + 4, 16);
            inet_ntop(AF_INET6, &addr6, conn->target_host,
                      sizeof(conn->target_host));
        }
        port = (uint16_t)((conn->buf[4 + addr_len] << 8)
                          | conn->buf[4 + addr_len + 1]);
        conn->target_port = port;
        consumed = total_needed;

    } else {
        resp[0] = 5;
        resp[1] = 8; /* address type not supported */
        resp[2] = 0;
        resp[3] = 1;
        memset(resp + 4, 0, 6);
        send_raw(conn, resp, 10);
        do_close_conn(conn);
        return;
    }

    /* Send success response: BND.ADDR = 0.0.0.0, BND.PORT = 0 */
    resp[0] = 5;
    resp[1] = 0; /* success */
    resp[2] = 0;
    resp[3] = 1; /* ATYP=IPv4 */
    memset(resp + 4, 0, 6);
    send_raw(conn, resp, 10);

    /* Consume request bytes */
    conn->buf_len -= consumed;
    if (conn->buf_len > 0) {
        memmove(conn->buf, conn->buf + consumed, conn->buf_len);
    }

    conn->state = S5_STATE_CONNECTED;

    /* Notify caller */
    if (conn->on_connect) {
        conn->on_connect(conn, conn->target_host, conn->target_port,
                         conn->userdata);
    }

    /* If there's leftover data after the request, deliver it */
    if (conn->buf_len > 0 && conn->on_data) {
        conn->on_data(conn, conn->buf, conn->buf_len, conn->userdata);
        conn->buf_len = 0;
    }
}

static void read_cb(uv_stream_t *stream, ssize_t nread, const uv_buf_t *buf)
{
    socks5_conn_t *conn = (socks5_conn_t *)stream;

    (void)buf;

    if (nread < 0) {
        do_close_conn(conn);
        return;
    }

    if (nread == 0) {
        return;
    }

    conn->buf_len += (size_t)nread;

    switch (conn->state) {
    case S5_STATE_GREETING:
        handle_greeting(conn);
        /* May transition to S5_STATE_REQUEST */
        if (conn->state == S5_STATE_REQUEST) {
            handle_request(conn);
        }
        break;

    case S5_STATE_REQUEST:
        handle_request(conn);
        break;

    case S5_STATE_CONNECTED:
        if (conn->on_data) {
            conn->on_data(conn, conn->buf, conn->buf_len, conn->userdata);
        }
        conn->buf_len = 0;
        break;

    default:
        break;
    }
}

/* ------------------------------------------------------------------ */
/* Server accept callback                                               */
/* ------------------------------------------------------------------ */

static void on_new_connection(uv_stream_t *server, int status)
{
    socks5_server_t *srv  = (socks5_server_t *)server;
    socks5_conn_t   *conn;

    if (status < 0) {
        LOG_WARN("socks5 accept error: %s", uv_strerror(status));
        return;
    }

    conn = (socks5_conn_t *)malloc(sizeof(socks5_conn_t));
    if (!conn) {
        LOG_ERROR("socks5: out of memory");
        return;
    }

    memset(conn, 0, sizeof(*conn));
    conn->state      = S5_STATE_GREETING;
    conn->on_connect = srv->on_connect;
    conn->on_data    = srv->on_data;
    conn->on_close   = srv->on_close;
    conn->userdata   = srv->userdata;

    uv_tcp_init(srv->loop, &conn->tcp);

    if (uv_accept(server, (uv_stream_t *)&conn->tcp) != 0) {
        uv_close((uv_handle_t *)&conn->tcp, NULL);
        free(conn);
        return;
    }

    uv_read_start((uv_stream_t *)&conn->tcp, alloc_cb, read_cb);
}

/* ------------------------------------------------------------------ */
/* Public API                                                           */
/* ------------------------------------------------------------------ */

err_t socks5_server_init(socks5_server_t *srv, uv_loop_t *loop,
                          const char *bind_addr, uint16_t port)
{
    struct sockaddr_in addr;
    int                r;

    if (!srv || !loop || !bind_addr) {
        return ERR_INVAL;
    }

    memset(srv, 0, sizeof(*srv));
    srv->loop = loop;

    r = uv_tcp_init(loop, &srv->server);
    if (r < 0) {
        return ERR_IO;
    }

    r = uv_ip4_addr(bind_addr, port, &addr);
    if (r < 0) {
        return ERR_INVAL;
    }

    r = uv_tcp_bind(&srv->server, (const struct sockaddr *)&addr, 0);
    if (r < 0) {
        return ERR_IO;
    }

    return ERR_OK;
}

err_t socks5_server_start(socks5_server_t *srv)
{
    int r;

    if (!srv) {
        return ERR_INVAL;
    }

    r = uv_listen((uv_stream_t *)&srv->server, 128, on_new_connection);
    if (r < 0) {
        return ERR_IO;
    }

    return ERR_OK;
}

static void server_close_cb(uv_handle_t *handle)
{
    (void)handle;
}

void socks5_server_stop(socks5_server_t *srv)
{
    if (!srv) {
        return;
    }
    if (!uv_is_closing((uv_handle_t *)&srv->server)) {
        uv_close((uv_handle_t *)&srv->server, server_close_cb);
    }
}

err_t socks5_conn_send(socks5_conn_t *conn, const uint8_t *data, size_t len)
{
    if (!conn || !data || len == 0) {
        return ERR_INVAL;
    }
    if (conn->closed) {
        return ERR_IO;
    }
    return send_raw(conn, data, len);
}

void socks5_conn_close(socks5_conn_t *conn)
{
    if (!conn) {
        return;
    }
    do_close_conn(conn);
}
