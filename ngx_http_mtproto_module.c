/*
 * ngx_http_mtproto_module — MTProto proxy with FakeTLS as an nginx HTTP module.
 *
 * Intercepts TLS ClientHello before OpenSSL, verifies HMAC to detect MTProto
 * clients.  Non-matching connections fall through to normal nginx SSL + HTTP.
 */

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include <ngx_event.h>
#include <openssl/hmac.h>
#include <openssl/sha.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <sys/socket.h>

/* ── Forward declarations ─────────────────────────────────────────────── */

typedef struct ngx_http_mtproto_srv_conf_s  ngx_http_mtproto_srv_conf_t;
typedef struct ngx_http_mtproto_dc_s        ngx_http_mtproto_dc_t;
typedef struct ngx_http_mtproto_ctx_s       ngx_http_mtproto_ctx_t;

static void *ngx_http_mtproto_create_srv_conf(ngx_conf_t *cf);
static char *ngx_http_mtproto_merge_srv_conf(ngx_conf_t *cf, void *parent,
    void *child);
static ngx_int_t ngx_http_mtproto_postconfiguration(ngx_conf_t *cf);
static char *ngx_http_mtproto_proxy_dc(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);
static char *ngx_http_mtproto_proxy_secret(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);

static void ngx_http_mtproto_handler(ngx_connection_t *c);
static void ngx_http_mtproto_preread(ngx_event_t *rev);
static void ngx_http_mtproto_fallback(ngx_http_mtproto_ctx_t *ctx);
static ngx_int_t ngx_http_mtproto_verify_hmac(ngx_http_mtproto_ctx_t *ctx,
    u_char *data, size_t len);
static ngx_int_t ngx_http_mtproto_send_server_hello(ngx_http_mtproto_ctx_t *ctx);
static void ngx_http_mtproto_client_read_obfs_header(ngx_event_t *rev);
static ngx_int_t ngx_http_mtproto_parse_obfs_header(ngx_http_mtproto_ctx_t *ctx,
    u_char *data, size_t len);
static void ngx_http_mtproto_connect_dc(ngx_http_mtproto_ctx_t *ctx);
static void ngx_http_mtproto_dc_connect_handler(ngx_event_t *wev);
static void ngx_http_mtproto_dc_read_handler(ngx_event_t *rev);
static void ngx_http_mtproto_client_read_handler(ngx_event_t *rev);
static void ngx_http_mtproto_dc_write_handler(ngx_event_t *wev);
static void ngx_http_mtproto_client_write_handler(ngx_event_t *wev);
static void ngx_http_mtproto_close(ngx_http_mtproto_ctx_t *ctx);
static void ngx_http_mtproto_cleanup(void *data);
static ngx_int_t ngx_http_mtproto_flush_buf(ngx_connection_t *c, u_char *buf,
    size_t *pos, size_t *len);

/* ── Constants ────────────────────────────────────────────────────────── */

#define MTPROTO_PREREAD_BUF     16384
#define MTPROTO_RELAY_BUF       32768
#define MTPROTO_TLS_HEADER_LEN  5
#define MTPROTO_TLS_MAX_PAYLOAD 16384
#define MTPROTO_OBFS2_HEADER    64

/* dbuf must hold MTPROTO_RELAY_BUF of encrypted data + TLS framing overhead:
 * ceil(32768/16384) * 5 = 10 bytes.  Round up generously. */
#define MTPROTO_DBUF_SIZE       (MTPROTO_RELAY_BUF + 256)

/* connection states */
#define MTPROTO_STATE_PREREAD        0
#define MTPROTO_STATE_HELLO_SENT     1
#define MTPROTO_STATE_OBFS_HEADER    2
#define MTPROTO_STATE_DC_CONNECTING  3
#define MTPROTO_STATE_RELAY          4
#define MTPROTO_STATE_DONE           5

/* ── Data structures ──────────────────────────────────────────────────── */

struct ngx_http_mtproto_dc_s {
    ngx_int_t           dc_id;
    struct sockaddr_in   addr;
};

struct ngx_http_mtproto_srv_conf_s {
    ngx_flag_t                    enable;
    u_char                        secret[16];
    ngx_flag_t                    secret_set;
    ngx_msec_t                    timeout;
    ngx_int_t                     default_dc;
    ngx_array_t                  *dcs;
    ngx_connection_handler_pt     orig_handler;
};

struct ngx_http_mtproto_ctx_s {
    unsigned                      state;
    ngx_connection_t             *client_conn;
    ngx_connection_t             *dc_conn;

    /* preread buffer (client hello) */
    u_char                       *preread_data;
    size_t                        preread_len;
    size_t                        preread_pos;

    /* relay buffers */
    u_char                       *cbuf;           /* client → DC */
    size_t                        cbuf_len;
    size_t                        cbuf_pos;
    u_char                       *dbuf;           /* DC → client */
    size_t                        dbuf_len;
    size_t                        dbuf_pos;

    /* TLS record reassembly for client reads */
    u_char                        tls_hdr[MTPROTO_TLS_HEADER_LEN];
    size_t                        tls_hdr_len;
    size_t                        tls_payload_remain;
    ngx_flag_t                    tls_in_payload;

    /* AES-CTR crypto contexts */
    EVP_CIPHER_CTX               *c_dec;          /* decrypt from client */
    EVP_CIPHER_CTX               *c_enc;          /* encrypt to client */
    EVP_CIPHER_CTX               *d_dec;          /* decrypt from DC */
    EVP_CIPHER_CTX               *d_enc;          /* encrypt to DC */

    /* from ClientHello */
    u_char                        session_id[32];
    ngx_uint_t                    session_id_len;
    u_char                        client_random[32];

    ngx_int_t                     dc_id;
    uint32_t                      proto_tag;

    ngx_pool_t                   *pool;
    ngx_http_mtproto_srv_conf_t  *conf;

};

/* ── Directives ───────────────────────────────────────────────────────── */

static ngx_command_t ngx_http_mtproto_commands[] = {

    { ngx_string("mtproto_proxy"),
      NGX_HTTP_SRV_CONF|NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_HTTP_SRV_CONF_OFFSET,
      offsetof(ngx_http_mtproto_srv_conf_t, enable),
      NULL },

    { ngx_string("mtproto_proxy_secret"),
      NGX_HTTP_SRV_CONF|NGX_CONF_TAKE1,
      ngx_http_mtproto_proxy_secret,
      NGX_HTTP_SRV_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("mtproto_proxy_timeout"),
      NGX_HTTP_SRV_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_msec_slot,
      NGX_HTTP_SRV_CONF_OFFSET,
      offsetof(ngx_http_mtproto_srv_conf_t, timeout),
      NULL },

    { ngx_string("mtproto_proxy_dc"),
      NGX_HTTP_SRV_CONF|NGX_CONF_TAKE2,
      ngx_http_mtproto_proxy_dc,
      NGX_HTTP_SRV_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("mtproto_proxy_dc_default"),
      NGX_HTTP_SRV_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_num_slot,
      NGX_HTTP_SRV_CONF_OFFSET,
      offsetof(ngx_http_mtproto_srv_conf_t, default_dc),
      NULL },

      ngx_null_command
};

/* ── Module context & definition ──────────────────────────────────────── */

static ngx_http_module_t ngx_http_mtproto_module_ctx = {
    NULL,                                  /* preconfiguration */
    ngx_http_mtproto_postconfiguration,    /* postconfiguration */

    NULL,                                  /* create main conf */
    NULL,                                  /* init main conf */

    ngx_http_mtproto_create_srv_conf,      /* create srv conf */
    ngx_http_mtproto_merge_srv_conf,       /* merge srv conf */

    NULL,                                  /* create loc conf */
    NULL                                   /* merge loc conf */
};

ngx_module_t ngx_http_mtproto_module = {
    NGX_MODULE_V1,
    &ngx_http_mtproto_module_ctx,          /* module context */
    ngx_http_mtproto_commands,             /* module directives */
    NGX_HTTP_MODULE,                       /* module type */
    NULL,                                  /* init master */
    NULL,                                  /* init module */
    NULL,                                  /* init process */
    NULL,                                  /* init thread */
    NULL,                                  /* exit thread */
    NULL,                                  /* exit process */
    NULL,                                  /* exit master */
    NGX_MODULE_V1_PADDING
};

/* ── Configuration ────────────────────────────────────────────────────── */

static void *
ngx_http_mtproto_create_srv_conf(ngx_conf_t *cf)
{
    ngx_http_mtproto_srv_conf_t  *conf;

    conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_mtproto_srv_conf_t));
    if (conf == NULL) {
        return NULL;
    }

    conf->enable = NGX_CONF_UNSET;
    conf->timeout = NGX_CONF_UNSET_MSEC;
    conf->default_dc = NGX_CONF_UNSET;
    conf->secret_set = 0;
    conf->orig_handler = NULL;

    return conf;
}

static char *
ngx_http_mtproto_merge_srv_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_http_mtproto_srv_conf_t *prev = parent;
    ngx_http_mtproto_srv_conf_t *conf = child;

    ngx_conf_merge_value(conf->enable, prev->enable, 0);
    ngx_conf_merge_msec_value(conf->timeout, prev->timeout, 30000);
    ngx_conf_merge_value(conf->default_dc, prev->default_dc, 2);

    if (!conf->secret_set && prev->secret_set) {
        ngx_memcpy(conf->secret, prev->secret, 16);
        conf->secret_set = 1;
    }

    if (conf->dcs == NULL) {
        conf->dcs = prev->dcs;
    }

    return NGX_CONF_OK;
}

static char *
ngx_http_mtproto_proxy_secret(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_mtproto_srv_conf_t *mscf = conf;
    ngx_str_t                   *value;
    size_t                       i;
    u_char                       hi, lo;

    value = cf->args->elts;

    if (value[1].len != 32) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "mtproto_proxy_secret must be 32 hex characters");
        return NGX_CONF_ERROR;
    }

    for (i = 0; i < 16; i++) {
        hi = value[1].data[i * 2];
        lo = value[1].data[i * 2 + 1];

        if (hi >= '0' && hi <= '9') { hi -= '0'; }
        else if (hi >= 'a' && hi <= 'f') { hi = hi - 'a' + 10; }
        else if (hi >= 'A' && hi <= 'F') { hi = hi - 'A' + 10; }
        else {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "invalid hex character in mtproto_proxy_secret");
            return NGX_CONF_ERROR;
        }

        if (lo >= '0' && lo <= '9') { lo -= '0'; }
        else if (lo >= 'a' && lo <= 'f') { lo = lo - 'a' + 10; }
        else if (lo >= 'A' && lo <= 'F') { lo = lo - 'A' + 10; }
        else {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "invalid hex character in mtproto_proxy_secret");
            return NGX_CONF_ERROR;
        }

        mscf->secret[i] = (hi << 4) | lo;
    }

    mscf->secret_set = 1;
    return NGX_CONF_OK;
}

static char *
ngx_http_mtproto_proxy_dc(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_mtproto_srv_conf_t *mscf = conf;
    ngx_str_t                   *value;
    ngx_http_mtproto_dc_t       *dc;
    ngx_url_t                    u;

    value = cf->args->elts;

    if (mscf->dcs == NULL) {
        mscf->dcs = ngx_array_create(cf->pool, 5,
                                     sizeof(ngx_http_mtproto_dc_t));
        if (mscf->dcs == NULL) {
            return NGX_CONF_ERROR;
        }
    }

    dc = ngx_array_push(mscf->dcs);
    if (dc == NULL) {
        return NGX_CONF_ERROR;
    }

    dc->dc_id = ngx_atoi(value[1].data, value[1].len);
    if (dc->dc_id == NGX_ERROR || dc->dc_id < 1 || dc->dc_id > 10) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "invalid DC id \"%V\"", &value[1]);
        return NGX_CONF_ERROR;
    }

    ngx_memzero(&u, sizeof(ngx_url_t));
    u.url = value[2];
    u.default_port = 443;

    if (ngx_parse_url(cf->pool, &u) != NGX_OK) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "invalid DC address \"%V\"", &value[2]);
        return NGX_CONF_ERROR;
    }

    ngx_memzero(&dc->addr, sizeof(struct sockaddr_in));
    dc->addr.sin_family = AF_INET;
    dc->addr.sin_port = u.port ? htons(u.port) : htons(443);

    /* ngx_parse_url resolves the address into u.addrs */
    if (u.addrs && u.addrs[0].sockaddr) {
        struct sockaddr_in *sin = (struct sockaddr_in *) u.addrs[0].sockaddr;
        dc->addr.sin_addr = sin->sin_addr;
        dc->addr.sin_port = sin->sin_port;
    } else {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "could not resolve DC address \"%V\"", &value[2]);
        return NGX_CONF_ERROR;
    }

    return NGX_CONF_OK;
}

/* ── Postconfiguration — hook listener handlers ───────────────────────── */

static ngx_int_t
ngx_http_mtproto_postconfiguration(ngx_conf_t *cf)
{
    ngx_http_core_srv_conf_t     *cscf;
    ngx_http_mtproto_srv_conf_t  *mscf;
    ngx_http_core_main_conf_t    *cmcf;
    ngx_http_conf_port_t         *port;
    ngx_http_conf_addr_t         *addr;
    ngx_uint_t                    p, a, s;
    ngx_http_core_srv_conf_t    **servers;

    cmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_core_module);

    if (cmcf->ports == NULL) {
        return NGX_OK;
    }

    port = cmcf->ports->elts;

    for (p = 0; p < cmcf->ports->nelts; p++) {
        addr = port[p].addrs.elts;

        for (a = 0; a < port[p].addrs.nelts; a++) {

            /* check if any server on this address has mtproto enabled */
            if (addr[a].servers.nelts == 0) {
                continue;
            }

            servers = addr[a].servers.elts;

            for (s = 0; s < addr[a].servers.nelts; s++) {
                cscf = servers[s];
                mscf = cscf->ctx->srv_conf[ngx_http_mtproto_module.ctx_index];

                if (mscf->enable) {
                    /*
                     * We need to remember the original handler so we can
                     * fall back.  At this stage the listening socket hasn't
                     * been created yet — we'll do the hook in init_process
                     * or at connection accept time.  But we can mark the
                     * srv_conf so we know to check later.
                     *
                     * Actually, at postconfiguration the listening sockets
                     * aren't set up yet.  We store the conf so the handler
                     * can find it.
                     */
                    ngx_log_error(NGX_LOG_NOTICE, cf->log, 0,
                                  "mtproto: enabled for server \"%V\"",
                                  &cscf->server_name);
                }
            }
        }
    }

    return NGX_OK;
}

/* ── Init process — hook listening socket handlers ────────────────────── */

/*
 * We use a process init handler to walk the listening sockets (which are
 * created after postconfiguration) and replace their handlers.
 *
 * This is set up via the module init_process callback.
 */

static ngx_int_t ngx_http_mtproto_init_process(ngx_cycle_t *cycle);

/* Patch the module definition to include init_process */
/* We do this via a constructor or directly — but since the module struct
   is already defined above, we set it in postconfiguration via a trick:
   we directly assign the function pointer. */

/* Actually, let's use a proper approach: define init_process in the module
   struct.  We need to go back and set it.  Since the struct is already
   defined, we'll use __attribute__((constructor)) to patch it. */

static void __attribute__((constructor))
ngx_http_mtproto_patch_module(void)
{
    ngx_http_mtproto_module.init_process = ngx_http_mtproto_init_process;
}

static ngx_int_t
ngx_http_mtproto_init_process(ngx_cycle_t *cycle)
{
    ngx_listening_t              *ls;
    ngx_uint_t                    i;
    ngx_http_port_t              *hport;
    ngx_http_in_addr_t           *hia;
    ngx_http_core_srv_conf_t     *cscf;
    ngx_http_mtproto_srv_conf_t  *mscf;
    ngx_uint_t                    a;

    ls = cycle->listening.elts;

    for (i = 0; i < cycle->listening.nelts; i++) {

        if (ls[i].handler == NULL) {
            continue;
        }

        /* Only hook HTTP listening sockets */
        hport = ls[i].servers;
        if (hport == NULL) {
            continue;
        }

        /* Check if any virtual server on this port has mtproto enabled */
        hia = hport->addrs;
        if (hia == NULL) {
            continue;
        }

        for (a = 0; a < hport->naddrs; a++) {
            /* Check the default server first */
            cscf = hia[a].conf.default_server;
            if (cscf == NULL) {
                continue;
            }

            mscf = cscf->ctx->srv_conf[ngx_http_mtproto_module.ctx_index];

            if (mscf && mscf->enable) {
                if (mscf->orig_handler == NULL) {
                    mscf->orig_handler = ls[i].handler;
                    ls[i].handler = ngx_http_mtproto_handler;

                    ngx_log_error(NGX_LOG_NOTICE, cycle->log, 0,
                                  "mtproto: hooked listener on %V",
                                  &ls[i].addr_text);
                }
                break;
            }
        }
    }

    return NGX_OK;
}

/* ── Helper: find srv_conf for connection ─────────────────────────────── */

static ngx_http_mtproto_srv_conf_t *
ngx_http_mtproto_get_conf(ngx_connection_t *c)
{
    ngx_http_port_t              *hport;
    ngx_http_in_addr_t           *hia;
    ngx_http_core_srv_conf_t     *cscf;
    ngx_http_mtproto_srv_conf_t  *mscf;

    if (c->listening == NULL || c->listening->servers == NULL) {
        return NULL;
    }

    hport = c->listening->servers;
    hia = hport->addrs;

    if (hia == NULL || hport->naddrs == 0) {
        return NULL;
    }

    /* Use first addr's default server */
    cscf = hia[0].conf.default_server;
    if (cscf == NULL) {
        return NULL;
    }

    mscf = cscf->ctx->srv_conf[ngx_http_mtproto_module.ctx_index];
    return mscf;
}

/* ── Helper: find DC address by id ────────────────────────────────────── */

static ngx_http_mtproto_dc_t *
ngx_http_mtproto_find_dc(ngx_http_mtproto_srv_conf_t *conf, ngx_int_t dc_id)
{
    ngx_http_mtproto_dc_t  *dcs;
    ngx_uint_t              i;

    if (conf->dcs == NULL) {
        return NULL;
    }

    dcs = conf->dcs->elts;
    for (i = 0; i < conf->dcs->nelts; i++) {
        if (dcs[i].dc_id == dc_id) {
            return &dcs[i];
        }
    }

    return NULL;
}

/* ── Connection handler — called on accept ────────────────────────────── */

static void
ngx_http_mtproto_handler(ngx_connection_t *c)
{
    ngx_http_mtproto_srv_conf_t  *mscf;
    ngx_http_mtproto_ctx_t       *ctx;
    ngx_pool_t                   *pool;

    mscf = ngx_http_mtproto_get_conf(c);

    if (mscf == NULL || !mscf->enable) {
        /* Should not happen, but fall back */
        if (mscf && mscf->orig_handler) {
            mscf->orig_handler(c);
        }
        return;
    }

    ngx_log_error(NGX_LOG_INFO, c->log, 0,
                  "mtproto: new connection from %V", &c->addr_text);

    pool = ngx_create_pool(4096, c->log);
    if (pool == NULL) {
        ngx_close_connection(c);
        return;
    }

    ctx = ngx_pcalloc(pool, sizeof(ngx_http_mtproto_ctx_t));
    if (ctx == NULL) {
        ngx_destroy_pool(pool);
        ngx_close_connection(c);
        return;
    }

    ctx->pool = pool;
    ctx->client_conn = c;
    ctx->conf = mscf;
    ctx->state = MTPROTO_STATE_PREREAD;
    ctx->dc_id = mscf->default_dc;

    ctx->preread_data = ngx_pcalloc(pool, MTPROTO_PREREAD_BUF);
    if (ctx->preread_data == NULL) {
        ngx_destroy_pool(pool);
        ngx_close_connection(c);
        return;
    }
    ctx->preread_len = 0;
    ctx->preread_pos = 0;

    /* store ctx on the connection */
    c->data = ctx;

    /* register cleanup */
    ngx_pool_cleanup_t *cln = ngx_pool_cleanup_add(pool, 0);
    if (cln) {
        cln->handler = ngx_http_mtproto_cleanup;
        cln->data = ctx;
    }

    /* set up read event for preread */
    c->read->handler = ngx_http_mtproto_preread;
    c->write->handler = ngx_http_mtproto_client_write_handler;

    /* add timeout */
    ngx_add_timer(c->read, mscf->timeout);

    if (c->read->ready) {
        ngx_http_mtproto_preread(c->read);
        return;
    }

    if (ngx_handle_read_event(c->read, 0) != NGX_OK) {
        ngx_destroy_pool(pool);
        ngx_close_connection(c);
    }
}

/* ── Preread — peek at ClientHello via MSG_PEEK and check HMAC ────────── */

static void
ngx_http_mtproto_preread(ngx_event_t *rev)
{
    ngx_connection_t             *c;
    ngx_http_mtproto_ctx_t       *ctx;
    ssize_t                       n;

    c = rev->data;
    ctx = c->data;

    if (rev->timedout) {
        ngx_log_error(NGX_LOG_INFO, c->log, 0,
                      "mtproto: preread timeout");
        ngx_http_mtproto_close(ctx);
        return;
    }

    /*
     * Use MSG_PEEK so data stays in the kernel socket buffer.
     * If HMAC doesn't match we just call the original handler and
     * nginx reads the same bytes from the socket normally.
     */
    n = recv(c->fd, ctx->preread_data, MTPROTO_PREREAD_BUF, MSG_PEEK);

    if (n == -1) {
        if (ngx_socket_errno == NGX_EAGAIN) {
            if (ngx_handle_read_event(rev, 0) != NGX_OK) {
                ngx_http_mtproto_close(ctx);
            }
            return;
        }
        ngx_log_error(NGX_LOG_ERR, c->log, ngx_socket_errno,
                      "mtproto: recv(MSG_PEEK) failed");
        ngx_http_mtproto_close(ctx);
        return;
    }

    if (n == 0) {
        ngx_log_error(NGX_LOG_INFO, c->log, 0,
                      "mtproto: preread connection closed");
        ngx_http_mtproto_close(ctx);
        return;
    }

    ctx->preread_len = n;

    ngx_log_error(NGX_LOG_DEBUG, c->log, 0,
                  "mtproto: peeked %z bytes", n);

    /* Need at least a TLS record header */
    if (ctx->preread_len < MTPROTO_TLS_HEADER_LEN) {
        if (ngx_handle_read_event(rev, 0) != NGX_OK) {
            ngx_http_mtproto_close(ctx);
        }
        return;
    }

    /* Check it looks like a TLS record */
    if (ctx->preread_data[0] != 0x16) {
        ngx_log_error(NGX_LOG_INFO, c->log, 0,
                      "mtproto: not a TLS record (0x%02xd), falling back",
                      ctx->preread_data[0]);
        ngx_http_mtproto_fallback(ctx);
        return;
    }

    /* TLS record length */
    size_t tls_record_len = (ctx->preread_data[3] << 8) | ctx->preread_data[4];
    size_t total_needed = MTPROTO_TLS_HEADER_LEN + tls_record_len;

    if (total_needed > MTPROTO_PREREAD_BUF) {
        ngx_log_error(NGX_LOG_INFO, c->log, 0,
                      "mtproto: TLS record too large (%uz), falling back",
                      tls_record_len);
        ngx_http_mtproto_fallback(ctx);
        return;
    }

    if (ctx->preread_len < total_needed) {
        /* Not enough data yet — wait for more */
        if (ngx_handle_read_event(rev, 0) != NGX_OK) {
            ngx_http_mtproto_close(ctx);
        }
        return;
    }

    /* We have the full TLS record — verify HMAC */
    if (ngx_http_mtproto_verify_hmac(ctx, ctx->preread_data, total_needed)
        == NGX_OK)
    {
        ngx_log_error(NGX_LOG_DEBUG, c->log, 0,
                      "mtproto: HMAC verified — MTProto client detected");

        /*
         * Now actually consume the ClientHello from the socket buffer
         * so it doesn't get re-read.
         */
        n = recv(c->fd, ctx->preread_data, total_needed, 0);
        if (n < (ssize_t) total_needed) {
            ngx_log_error(NGX_LOG_ERR, c->log, ngx_socket_errno,
                          "mtproto: failed to consume ClientHello");
            ngx_http_mtproto_close(ctx);
            return;
        }

        if (rev->timer_set) {
            ngx_del_timer(rev);
        }
        ngx_add_timer(rev, ctx->conf->timeout);

        /* Send FakeTLS ServerHello */
        if (ngx_http_mtproto_send_server_hello(ctx) != NGX_OK) {
            ngx_http_mtproto_close(ctx);
            return;
        }

        /* Now wait for obfuscated2 header from client */
        ctx->state = MTPROTO_STATE_OBFS_HEADER;
        ctx->preread_len = 0;  /* reuse buffer for obfs header */
        c->read->handler = ngx_http_mtproto_client_read_obfs_header;

        if (ngx_handle_read_event(c->read, 0) != NGX_OK) {
            ngx_http_mtproto_close(ctx);
        }
    } else {
        ngx_log_error(NGX_LOG_INFO, c->log, 0,
                      "mtproto: HMAC mismatch — falling back to nginx");
        ngx_http_mtproto_fallback(ctx);
    }
}

/* ── HMAC verification ────────────────────────────────────────────────── */

static ngx_int_t
ngx_http_mtproto_verify_hmac(ngx_http_mtproto_ctx_t *ctx, u_char *data,
    size_t len)
{
    u_char        *buf;
    u_char         expected[32];
    unsigned int   hmac_len;

    /*
     * ClientHello layout:
     *   [0]     = 0x16 (handshake)
     *   [1..2]  = TLS version
     *   [3..4]  = length
     *   [5]     = 0x01 (ClientHello handshake type)
     *   [6..8]  = handshake length (3 bytes)
     *   [9..10] = client version
     *   [11..42] = random (32 bytes) ← the HMAC we verify
     *   [43]    = session_id_len
     *   [44..]  = session_id
     */

    if (len < 44) {
        return NGX_ERROR;
    }

    /* Check handshake type */
    if (data[5] != 0x01) {
        return NGX_ERROR;
    }

    /* Save client_random (as sent, including timestamp XOR) */
    ngx_memcpy(ctx->client_random, data + 11, 32);

    /* Extract session_id */
    ngx_uint_t sid_len = data[43];
    if (sid_len > 32) {
        sid_len = 32;
    }
    ctx->session_id_len = sid_len;
    if (sid_len > 0 && len >= 44 + sid_len) {
        ngx_memcpy(ctx->session_id, &data[44], sid_len);
    }

    /* Make a copy and zero out the random field */
    buf = ngx_pnalloc(ctx->pool, len);
    if (buf == NULL) {
        return NGX_ERROR;
    }
    ngx_memcpy(buf, data, len);
    ngx_memzero(buf + 11, 32);  /* zero random[32] */

    /* Compute HMAC-SHA256 */
    hmac_len = 32;
    if (HMAC(EVP_sha256(), ctx->conf->secret, 16, buf, len,
             expected, &hmac_len) == NULL)
    {
        return NGX_ERROR;
    }

    /*
     * Telegram clients XOR a Unix timestamp (LE uint32) into bytes 28..31
     * of the random field.  Compare only the first 28 bytes, then extract
     * the timestamp and check it's within a reasonable window.
     */
    if (ngx_memcmp(expected, data + 11, 28) != 0) {
        return NGX_ERROR;
    }

    /* Extract and validate timestamp */
    uint32_t ts = 0;
    for (int i = 0; i < 4; i++) {
        ts |= (uint32_t)(expected[28 + i] ^ data[11 + 28 + i]) << (i * 8);
    }
    time_t now = ngx_time();
    int32_t diff = (int32_t)(now - (time_t) ts);
    if (diff < 0) { diff = -diff; }

    if (diff > 300) {
        ngx_log_error(NGX_LOG_WARN, ctx->client_conn->log, 0,
                      "mtproto: HMAC timestamp too far off: %d seconds", diff);
        return NGX_ERROR;
    }

    return NGX_OK;
}

/* ── Fallback to original nginx handler ───────────────────────────────── */

/*
 * Because we used MSG_PEEK, the ClientHello data is still in the kernel
 * socket buffer.  We just clean up our state and call the original
 * nginx connection handler — it will read the same bytes from the socket.
 */
static void
ngx_http_mtproto_fallback(ngx_http_mtproto_ctx_t *ctx)
{
    ngx_connection_t             *c = ctx->client_conn;
    ngx_http_mtproto_srv_conf_t  *mscf = ctx->conf;

    if (c->read->timer_set) {
        ngx_del_timer(c->read);
    }

    /* Prevent cleanup from closing the client connection */
    ctx->client_conn = NULL;
    ctx->state = MTPROTO_STATE_DONE;

    /* Free our pool (and crypto contexts via cleanup) */
    ngx_destroy_pool(ctx->pool);

    /* Call the original handler — data is still in socket buffer */
    if (mscf && mscf->orig_handler) {
        mscf->orig_handler(c);
    } else {
        ngx_close_connection(c);
    }
}

/* ── FakeTLS ServerHello ──────────────────────────────────────────────── */

static ngx_int_t
ngx_http_mtproto_send_server_hello(ngx_http_mtproto_ctx_t *ctx)
{
    ngx_connection_t  *c = ctx->client_conn;
    u_char             buf[4096];
    size_t             pos = 0;
    u_char             hmac_result[32];
    unsigned int       hmac_len;
    HMAC_CTX          *hctx;

    /*
     * TDLib verifies server response as:
     *   HMAC-SHA256(secret, client_random || full_response_with_random_zeroed)
     *
     * So we must:
     *   1. Build the entire response (ServerHello + CCS + AppData)
     *      with server_random = zeros
     *   2. Compute HMAC over (client_random || response)
     *   3. Place HMAC at offset 11 in the response
     *   4. Send
     */

    /* ── 1. ServerHello TLS record ─────────────────────────────────── */

    /* Handshake body */
    u_char sh_body[256];
    size_t sh_pos = 0;

    sh_body[sh_pos++] = 0x03;
    sh_body[sh_pos++] = 0x03;  /* version TLS 1.2 */

    /* server_random — zeros (placeholder for HMAC) */
    ngx_memzero(sh_body + sh_pos, 32);
    sh_pos += 32;

    /* session id echo */
    sh_body[sh_pos++] = (u_char) ctx->session_id_len;
    if (ctx->session_id_len > 0) {
        ngx_memcpy(sh_body + sh_pos, ctx->session_id, ctx->session_id_len);
        sh_pos += ctx->session_id_len;
    }

    /* cipher suite: TLS_AES_128_GCM_SHA256 */
    sh_body[sh_pos++] = 0x13;
    sh_body[sh_pos++] = 0x01;

    /* compression: null */
    sh_body[sh_pos++] = 0x00;

    /* extensions */
    u_char ext_buf[64];
    size_t ext_len = 0;

    /* key_share extension (0x0033) with x25519 — 36 bytes data */
    ext_buf[ext_len++] = 0x00; ext_buf[ext_len++] = 0x33; /* type */
    ext_buf[ext_len++] = 0x00; ext_buf[ext_len++] = 0x24; /* len=36 */
    ext_buf[ext_len++] = 0x00; ext_buf[ext_len++] = 0x1d; /* x25519 */
    ext_buf[ext_len++] = 0x00; ext_buf[ext_len++] = 0x20; /* key_len=32 */
    RAND_bytes(ext_buf + ext_len, 32);                     /* fake pubkey */
    ext_len += 32;

    /* supported_versions extension (0x002b) = TLS 1.3 */
    ext_buf[ext_len++] = 0x00; ext_buf[ext_len++] = 0x2b;
    ext_buf[ext_len++] = 0x00; ext_buf[ext_len++] = 0x02;
    ext_buf[ext_len++] = 0x03; ext_buf[ext_len++] = 0x04;

    /* extensions length */
    sh_body[sh_pos++] = (ext_len >> 8) & 0xff;
    sh_body[sh_pos++] = ext_len & 0xff;
    ngx_memcpy(sh_body + sh_pos, ext_buf, ext_len);
    sh_pos += ext_len;

    /* Handshake wrapper */
    size_t hs_len = 4 + sh_pos;

    /* TLS record header */
    buf[pos++] = 0x16;
    buf[pos++] = 0x03;
    buf[pos++] = 0x03;
    buf[pos++] = (hs_len >> 8) & 0xff;
    buf[pos++] = hs_len & 0xff;

    /* Handshake header */
    buf[pos++] = 0x02;  /* ServerHello */
    buf[pos++] = (sh_pos >> 16) & 0xff;
    buf[pos++] = (sh_pos >> 8) & 0xff;
    buf[pos++] = sh_pos & 0xff;

    /* Handshake body */
    ngx_memcpy(buf + pos, sh_body, sh_pos);
    pos += sh_pos;

    /* ── 2. ChangeCipherSpec ───────────────────────────────────────── */

    buf[pos++] = 0x14;
    buf[pos++] = 0x03;
    buf[pos++] = 0x03;
    buf[pos++] = 0x00;
    buf[pos++] = 0x01;
    buf[pos++] = 0x01;

    /* ── 3. Fake Application Data ──────────────────────────────────── */

    size_t fake_len = 1200 + (ngx_random() % 201);
    u_char *fake_data = ngx_pnalloc(ctx->pool, fake_len);
    if (fake_data == NULL) {
        return NGX_ERROR;
    }
    RAND_bytes(fake_data, fake_len);

    buf[pos++] = 0x17;
    buf[pos++] = 0x03;
    buf[pos++] = 0x03;
    buf[pos++] = (fake_len >> 8) & 0xff;
    buf[pos++] = fake_len & 0xff;
    ngx_memcpy(buf + pos, fake_data, fake_len);
    pos += fake_len;

    /* ── 4. Compute HMAC over (client_random || buf_with_random_zeroed) ── */

    /* buf[11..42] is already zeros — compute HMAC */
    hctx = HMAC_CTX_new();
    if (hctx == NULL) {
        return NGX_ERROR;
    }

    hmac_len = 32;
    HMAC_Init_ex(hctx, ctx->conf->secret, 16, EVP_sha256(), NULL);
    HMAC_Update(hctx, ctx->client_random, 32);
    HMAC_Update(hctx, buf, pos);
    HMAC_Final(hctx, hmac_result, &hmac_len);
    HMAC_CTX_free(hctx);

    /* Place HMAC in server_random field */
    ngx_memcpy(buf + 11, hmac_result, 32);

    /* ── 5. Send ───────────────────────────────────────────────────── */

    ssize_t sent = c->send(c, buf, pos);
    if (sent == NGX_ERROR) {
        ngx_log_error(NGX_LOG_ERR, c->log, 0,
                      "mtproto: failed to send ServerHello");
        return NGX_ERROR;
    }

    if ((size_t) sent != pos) {
        ngx_log_error(NGX_LOG_ERR, c->log, 0,
                      "mtproto: partial ServerHello send (%z/%uz)", sent, pos);
        return NGX_ERROR;
    }

    ngx_log_error(NGX_LOG_DEBUG, c->log, 0,
                  "mtproto: sent ServerHello (%uz bytes)", pos);

    ctx->state = MTPROTO_STATE_HELLO_SENT;
    return NGX_OK;
}

/* ── Read obfuscated2 header (inside TLS Application Data) ───────────── */

static void
ngx_http_mtproto_client_read_obfs_header(ngx_event_t *rev)
{
    ngx_connection_t          *c;
    ngx_http_mtproto_ctx_t    *ctx;
    ssize_t                    n;

    c = rev->data;
    ctx = c->data;

    if (rev->timedout) {
        ngx_log_error(NGX_LOG_INFO, c->log, 0,
                      "mtproto: obfs header read timeout");
        ngx_http_mtproto_close(ctx);
        return;
    }

    /* Read into preread_data buffer (reused) */
    n = c->recv(c, ctx->preread_data + ctx->preread_len,
                MTPROTO_PREREAD_BUF - ctx->preread_len);

    if (n == NGX_AGAIN) {
        if (ngx_handle_read_event(rev, 0) != NGX_OK) {
            ngx_http_mtproto_close(ctx);
        }
        return;
    }

    if (n == 0) {
        ngx_log_error(NGX_LOG_INFO, c->log, 0,
                      "mtproto: obfs header: client closed connection (EOF)");
        ngx_http_mtproto_close(ctx);
        return;
    }

    if (n == NGX_ERROR) {
        ngx_log_error(NGX_LOG_ERR, c->log, ngx_socket_errno,
                      "mtproto: obfs header: recv error");
        ngx_http_mtproto_close(ctx);
        return;
    }

    ctx->preread_len += n;

    /*
     * Client sends CCS (0x14) then AppData (0x17).
     * Skip any CCS records before the AppData.
     */
    size_t skip = 0;
    while (skip + MTPROTO_TLS_HEADER_LEN <= ctx->preread_len
           && ctx->preread_data[skip] == 0x14)
    {
        size_t ccs_len = (ctx->preread_data[skip + 3] << 8)
                         | ctx->preread_data[skip + 4];
        skip += MTPROTO_TLS_HEADER_LEN + ccs_len;
    }

    if (skip > 0 && skip <= ctx->preread_len) {
        /* Shift buffer past CCS records */
        ctx->preread_len -= skip;
        if (ctx->preread_len > 0) {
            ngx_memmove(ctx->preread_data,
                        ctx->preread_data + skip, ctx->preread_len);
        }
    }

    /*
     * Now expect a TLS Application Data record containing at least 64 bytes.
     * Record: [0x17, 0x03, 0x03, len_hi, len_lo, payload...]
     */
    if (ctx->preread_len < MTPROTO_TLS_HEADER_LEN) {
        if (ngx_handle_read_event(rev, 0) != NGX_OK) {
            ngx_http_mtproto_close(ctx);
        }
        return;
    }

    if (ctx->preread_data[0] != 0x17) {
        ngx_log_error(NGX_LOG_ERR, c->log, 0,
                      "mtproto: expected AppData record, got 0x%02xd",
                      ctx->preread_data[0]);
        ngx_http_mtproto_close(ctx);
        return;
    }

    size_t payload_len = (ctx->preread_data[3] << 8) | ctx->preread_data[4];
    size_t total_needed = MTPROTO_TLS_HEADER_LEN + payload_len;

    if (payload_len < MTPROTO_OBFS2_HEADER) {
        ngx_log_error(NGX_LOG_ERR, c->log, 0,
                      "mtproto: AppData payload too small for obfs2 header (%uz)",
                      payload_len);
        ngx_http_mtproto_close(ctx);
        return;
    }

    if (ctx->preread_len < total_needed) {
        if (ngx_handle_read_event(rev, 0) != NGX_OK) {
            ngx_http_mtproto_close(ctx);
        }
        return;
    }

    /* Parse the obfs2 header (skip 5-byte TLS header) */
    u_char *obfs_data = ctx->preread_data + MTPROTO_TLS_HEADER_LEN;

    if (ngx_http_mtproto_parse_obfs_header(ctx, obfs_data, payload_len)
        != NGX_OK)
    {
        ngx_log_error(NGX_LOG_ERR, c->log, 0,
                      "mtproto: failed to parse obfs2 header");
        ngx_http_mtproto_close(ctx);
        return;
    }

    /* Check for remaining data after the obfs2 header in this TLS record */
    size_t extra = payload_len - MTPROTO_OBFS2_HEADER;
    if (extra > 0) {
        /* There's extra data in this record — it's relay data from the client.
         * We need to save it for later forwarding to DC. */
        /* For now, we'll handle this in the relay phase. */
        /* Move the extra data to the start of cbuf */
        ctx->cbuf = ngx_pnalloc(ctx->pool, MTPROTO_RELAY_BUF);
        if (ctx->cbuf == NULL) {
            ngx_http_mtproto_close(ctx);
            return;
        }

        /* Decrypt the extra data with client decrypt key */
        int outl;
        EVP_EncryptUpdate(ctx->c_dec, ctx->cbuf, &outl,
                          obfs_data + MTPROTO_OBFS2_HEADER, extra);
        ctx->cbuf_len = outl;
        ctx->cbuf_pos = 0;
    }

    /* Also check for more TLS records after this one */
    size_t consumed = total_needed;
    size_t remaining = ctx->preread_len - consumed;
    if (remaining > 0 && ctx->cbuf == NULL) {
        /* Store remaining for later */
        ctx->cbuf = ngx_pnalloc(ctx->pool, MTPROTO_RELAY_BUF);
        if (ctx->cbuf == NULL) {
            ngx_http_mtproto_close(ctx);
            return;
        }
        ctx->cbuf_len = 0;
        ctx->cbuf_pos = 0;
    }

    ngx_log_error(NGX_LOG_DEBUG, c->log, 0,
                  "mtproto: obfs2 parsed, DC=%d, connecting...", ctx->dc_id);

    /* Connect to DC */
    ctx->state = MTPROTO_STATE_DC_CONNECTING;
    ngx_http_mtproto_connect_dc(ctx);
}

/* ── Parse obfuscated2 header ─────────────────────────────────────────── */

static ngx_int_t
ngx_http_mtproto_parse_obfs_header(ngx_http_mtproto_ctx_t *ctx,
    u_char *data, size_t len)
{
    u_char          nonce[64];
    u_char          enc_key_data[64];
    u_char          dec_key_data[64];
    u_char          enc_key[32], dec_key[32];
    u_char          enc_iv[16], dec_iv[16];
    u_char          skip_buf[64];
    int             outl;
    int16_t         dc_id;
    uint32_t        proto_tag;
    u_char          reversed[48];
    ngx_uint_t      i;

    if (len < MTPROTO_OBFS2_HEADER) {
        return NGX_ERROR;
    }

    ngx_memcpy(nonce, data, 64);

    /*
     * Client → Proxy decrypt key:
     *   encrypt_key = SHA256(nonce[8..39] || secret)
     *   encrypt_iv  = nonce[40..55]
     */
    ngx_memcpy(enc_key_data, nonce + 8, 32);
    ngx_memcpy(enc_key_data + 32, ctx->conf->secret, 16);
    SHA256(enc_key_data, 48, enc_key);
    ngx_memcpy(enc_iv, nonce + 40, 16);

    /*
     * Proxy → Client encrypt key:
     *   reversed    = reverse(nonce[8..55])
     *   decrypt_key = SHA256(reversed[0..31] || secret)
     *   decrypt_iv  = reversed[32..47]
     */
    for (i = 0; i < 48; i++) {
        reversed[i] = nonce[55 - i];
    }
    ngx_memcpy(dec_key_data, reversed, 32);
    ngx_memcpy(dec_key_data + 32, ctx->conf->secret, 16);
    SHA256(dec_key_data, 48, dec_key);
    ngx_memcpy(dec_iv, reversed + 32, 16);

    /*
     * Setup AES-256-CTR for client→proxy (decrypt incoming)
     */
    ctx->c_dec = EVP_CIPHER_CTX_new();
    if (ctx->c_dec == NULL) {
        return NGX_ERROR;
    }
    EVP_EncryptInit_ex(ctx->c_dec, EVP_aes_256_ctr(), NULL, enc_key, enc_iv);

    /*
     * Setup AES-256-CTR for proxy→client (encrypt outgoing)
     */
    ctx->c_enc = EVP_CIPHER_CTX_new();
    if (ctx->c_enc == NULL) {
        return NGX_ERROR;
    }
    EVP_EncryptInit_ex(ctx->c_enc, EVP_aes_256_ctr(), NULL, dec_key, dec_iv);

    /*
     * Skip first 56 bytes of client→proxy keystream, then decrypt nonce[56..63]
     */
    EVP_EncryptUpdate(ctx->c_dec, skip_buf, &outl, nonce, 56);

    u_char decrypted[8];
    EVP_EncryptUpdate(ctx->c_dec, decrypted, &outl, nonce + 56, 8);

    /* Extract protocol tag (bytes 0..3) and dc_id (bytes 4..5) */
    ngx_memcpy(&proto_tag, decrypted, 4);
    /* proto_tag is already in little-endian memory layout */
    /* Accept known protocol tags:
     *   0xeeeeeeee = intermediate
     *   0xdddddddd = abridged
     *   0xefefefef = full (rare)
     */
    if (proto_tag != 0xeeeeeeee && proto_tag != 0xdddddddd
        && proto_tag != 0xefefefef)
    {
        ngx_log_error(NGX_LOG_ERR, ctx->client_conn->log, 0,
                      "mtproto: unexpected protocol tag: 0x%08xd", proto_tag);
        return NGX_ERROR;
    }

    ctx->proto_tag = proto_tag;

    ngx_memcpy(&dc_id, decrypted + 4, 2);
    /* dc_id is little-endian int16 */
    if (dc_id < 0) {
        /* negative = test DC, take absolute value */
        dc_id = -dc_id;
    }

    if (dc_id < 1 || dc_id > 10) {
        ngx_log_error(NGX_LOG_ERR, ctx->client_conn->log, 0,
                      "mtproto: invalid DC id: %d", dc_id);
        return NGX_ERROR;
    }

    ctx->dc_id = dc_id;

    ngx_log_error(NGX_LOG_DEBUG, ctx->client_conn->log, 0,
                  "mtproto: obfs2 header parsed, proto=0x%08xd dc=%d",
                  proto_tag, dc_id);

    return NGX_OK;
}

/* ── DC connection ────────────────────────────────────────────────────── */

static void
ngx_http_mtproto_connect_dc(ngx_http_mtproto_ctx_t *ctx)
{
    ngx_http_mtproto_dc_t  *dc;
    ngx_peer_connection_t   pc;
    ngx_int_t               rc;
    ngx_connection_t        *c = ctx->client_conn;

    dc = ngx_http_mtproto_find_dc(ctx->conf, ctx->dc_id);
    if (dc == NULL) {
        ngx_log_error(NGX_LOG_ERR, c->log, 0,
                      "mtproto: DC %d not configured", ctx->dc_id);
        ngx_http_mtproto_close(ctx);
        return;
    }

    ngx_memzero(&pc, sizeof(ngx_peer_connection_t));

    pc.sockaddr = (struct sockaddr *) &dc->addr;
    pc.socklen = sizeof(struct sockaddr_in);

    /* format name for logging */
    u_char text[NGX_SOCKADDR_STRLEN];
    ngx_str_t addr_str;
    addr_str.data = text;
    addr_str.len = ngx_sock_ntop(pc.sockaddr, pc.socklen, text,
                                 NGX_SOCKADDR_STRLEN, 1);

    pc.name = &addr_str;
    pc.get = ngx_event_get_peer;
    pc.log = c->log;
    pc.log_error = NGX_ERROR_ERR;
    pc.rcvbuf = MTPROTO_RELAY_BUF;

    rc = ngx_event_connect_peer(&pc);

    if (rc == NGX_ERROR || rc == NGX_DECLINED) {
        ngx_log_error(NGX_LOG_ERR, c->log, 0,
                      "mtproto: failed to connect to DC %d", ctx->dc_id);
        ngx_http_mtproto_close(ctx);
        return;
    }

    ctx->dc_conn = pc.connection;
    ctx->dc_conn->data = ctx;
    ctx->dc_conn->pool = ctx->pool;

    /* Set up event handlers */
    ctx->dc_conn->read->handler = ngx_http_mtproto_dc_read_handler;
    ctx->dc_conn->write->handler = ngx_http_mtproto_dc_connect_handler;

    ngx_add_timer(ctx->dc_conn->write, ctx->conf->timeout);

    if (rc == NGX_OK) {
        /* Already connected */
        ngx_http_mtproto_dc_connect_handler(ctx->dc_conn->write);
    }
}

/* ── DC connect complete handler ──────────────────────────────────────── */

static void
ngx_http_mtproto_dc_connect_handler(ngx_event_t *wev)
{
    ngx_connection_t          *dc;
    ngx_http_mtproto_ctx_t    *ctx;
    ssize_t                    sent;
    u_char                     proto_init[4];

    dc = wev->data;
    ctx = dc->data;

    if (wev->timedout) {
        ngx_log_error(NGX_LOG_ERR, dc->log, 0,
                      "mtproto: DC connect timeout");
        ngx_http_mtproto_close(ctx);
        return;
    }

    if (wev->timer_set) {
        ngx_del_timer(wev);
    }

    /* Check for connect errors */
    int err = 0;
    socklen_t errlen = sizeof(int);
    if (getsockopt(dc->fd, SOL_SOCKET, SO_ERROR, &err, &errlen) == -1
        || err != 0)
    {
        ngx_log_error(NGX_LOG_ERR, dc->log, 0,
                      "mtproto: DC connect error: %d", err);
        ngx_http_mtproto_close(ctx);
        return;
    }

    ngx_log_error(NGX_LOG_DEBUG, dc->log, 0,
                  "mtproto: connected to DC %d", ctx->dc_id);

    /*
     * DC connection uses plain transport (no obfuscated2):
     *   - Send the client's protocol tag to DC
     *   - Relay plaintext data (no crypto on DC side)
     *
     * Using the same protocol tag as the client ensures padded intermediate
     * (0xdddddddd) data flows through correctly — DC expects padding too.
     */
    {
        ngx_memcpy(proto_init, &ctx->proto_tag, 4);
        sent = dc->send(dc, proto_init, 4);
        if (sent != 4) {
            ngx_log_error(NGX_LOG_ERR, dc->log, 0,
                          "mtproto: failed to send protocol init to DC");
            ngx_http_mtproto_close(ctx);
            return;
        }
        ngx_log_error(NGX_LOG_DEBUG, dc->log, 0,
                      "mtproto: DC %d using protocol tag 0x%08xd",
                      ctx->dc_id, ctx->proto_tag);
    }

    /* Allocate relay buffers if not yet done */
    if (ctx->cbuf == NULL) {
        ctx->cbuf = ngx_pnalloc(ctx->pool, MTPROTO_RELAY_BUF);
        if (ctx->cbuf == NULL) {
            ngx_http_mtproto_close(ctx);
            return;
        }
        ctx->cbuf_len = 0;
        ctx->cbuf_pos = 0;
    }

    if (ctx->dbuf == NULL) {
        ctx->dbuf = ngx_pnalloc(ctx->pool, MTPROTO_DBUF_SIZE);
        if (ctx->dbuf == NULL) {
            ngx_http_mtproto_close(ctx);
            return;
        }
        ctx->dbuf_len = 0;
        ctx->dbuf_pos = 0;
    }

    /* Enter relay mode */
    ctx->state = MTPROTO_STATE_RELAY;

    /* Set up event handlers for bidirectional proxying */
    ctx->client_conn->read->handler = ngx_http_mtproto_client_read_handler;
    ctx->client_conn->write->handler = ngx_http_mtproto_client_write_handler;
    ctx->dc_conn->read->handler = ngx_http_mtproto_dc_read_handler;
    ctx->dc_conn->write->handler = ngx_http_mtproto_dc_write_handler;

    /* If we have buffered data from the client (extra from obfs header TLS record),
     * try to flush it to DC now (already decrypted with c_dec) */
    if (ctx->cbuf_len > 0) {
        ngx_int_t rc;

        ngx_log_error(NGX_LOG_DEBUG, dc->log, 0,
                      "mtproto: forwarding %uz bytes to DC",
                      ctx->cbuf_len);

        rc = ngx_http_mtproto_flush_buf(dc, ctx->cbuf,
                                         &ctx->cbuf_pos, &ctx->cbuf_len);
        if (rc == NGX_ERROR) {
            ngx_log_error(NGX_LOG_ERR, dc->log, 0,
                          "mtproto: failed to send buffered data to DC");
            ngx_http_mtproto_close(ctx);
            return;
        }

        if (rc == NGX_AGAIN) {
            /* DC write buffer full — arm write event, skip client reads
             * until dc_write_handler flushes the buffer */
            if (ngx_handle_write_event(ctx->dc_conn->write, 0) != NGX_OK) {
                ngx_http_mtproto_close(ctx);
                return;
            }
            if (ngx_handle_read_event(ctx->dc_conn->read, 0) != NGX_OK) {
                ngx_http_mtproto_close(ctx);
                return;
            }
            ngx_add_timer(ctx->dc_conn->read, ctx->conf->timeout);

            ngx_log_error(NGX_LOG_DEBUG, ctx->client_conn->log, 0,
                          "mtproto: relay mode active, DC=%d", ctx->dc_id);
            return;
        }
    }

    /* Add timeouts */
    ngx_add_timer(ctx->client_conn->read, ctx->conf->timeout);
    ngx_add_timer(ctx->dc_conn->read, ctx->conf->timeout);

    /* Enable read events on both sides */
    if (ngx_handle_read_event(ctx->client_conn->read, 0) != NGX_OK) {
        ngx_http_mtproto_close(ctx);
        return;
    }
    if (ngx_handle_read_event(ctx->dc_conn->read, 0) != NGX_OK) {
        ngx_http_mtproto_close(ctx);
        return;
    }

    ngx_log_error(NGX_LOG_DEBUG, ctx->client_conn->log, 0,
                  "mtproto: relay mode active, DC=%d", ctx->dc_id);
}

/* ── Helper: flush send buffer, non-blocking ──────────────────────────── */

static ngx_int_t
ngx_http_mtproto_flush_buf(ngx_connection_t *c, u_char *buf,
    size_t *pos, size_t *len)
{
    ssize_t  n;

    while (*pos < *len) {
        n = c->send(c, buf + *pos, *len - *pos);

        if (n == NGX_ERROR) {
            return NGX_ERROR;
        }

        if (n == NGX_AGAIN || n == 0) {
            return NGX_AGAIN;
        }

        *pos += n;
    }

    /* All sent, reset buffer */
    *pos = 0;
    *len = 0;

    return NGX_OK;
}

/* ── Client → DC relay (read from client) ─────────────────────────────── */

static void
ngx_http_mtproto_client_read_handler(ngx_event_t *rev)
{
    ngx_connection_t          *c;
    ngx_http_mtproto_ctx_t    *ctx;
    ssize_t                    n;
    ngx_int_t                  rc;
    u_char                     raw[MTPROTO_RELAY_BUF];
    u_char                     decrypted[MTPROTO_RELAY_BUF];
    int                        outl;

    c = rev->data;
    ctx = c->data;

    if (ctx == NULL || ctx->state != MTPROTO_STATE_RELAY) {
        return;
    }

    if (rev->timedout) {
        ngx_log_error(NGX_LOG_INFO, c->log, 0,
                      "mtproto: client read timeout");
        ngx_http_mtproto_close(ctx);
        return;
    }

    /* If cbuf still has unsent data, try to flush first */
    if (ctx->cbuf_len > ctx->cbuf_pos) {
        rc = ngx_http_mtproto_flush_buf(ctx->dc_conn, ctx->cbuf,
                                         &ctx->cbuf_pos, &ctx->cbuf_len);
        if (rc == NGX_ERROR) {
            ngx_http_mtproto_close(ctx);
            return;
        }

        if (rc == NGX_AGAIN) {
            /* Still blocked — keep write event armed, deactivate read */
            if (ngx_handle_write_event(ctx->dc_conn->write, 0) != NGX_OK) {
                ngx_http_mtproto_close(ctx);
            }
            ngx_handle_read_event(rev, 0);
            return;
        }
    }

    /* Reset timeout */
    if (rev->timer_set) {
        ngx_del_timer(rev);
    }
    ngx_add_timer(rev, ctx->conf->timeout);

    for (;;) {
        n = c->recv(c, raw, sizeof(raw));

        if (n == NGX_AGAIN) {
            break;
        }

        if (n <= 0) {
            ngx_log_error(NGX_LOG_INFO, c->log, 0,
                          "mtproto: client disconnected");
            ngx_http_mtproto_close(ctx);
            return;
        }

        ngx_log_error(NGX_LOG_DEBUG, c->log, 0,
                      "mtproto: client sent %z bytes", n);

        /*
         * Process TLS record framing from client:
         * Each record: [type, 0x03, 0x03, len_hi, len_lo, payload...]
         * We strip headers and decrypt payloads into cbuf.
         * CCS records (0x14) are silently skipped.
         */
        size_t pos = 0;

        ctx->cbuf_pos = 0;
        ctx->cbuf_len = 0;

        while (pos < (size_t) n) {
            /* If we're in the middle of reading a TLS payload */
            if (ctx->tls_in_payload) {
                size_t chunk = ngx_min((size_t) n - pos,
                                       ctx->tls_payload_remain);

                if (ctx->tls_hdr[0] == 0x14) {
                    /* CCS record — skip payload silently */
                    pos += chunk;
                    ctx->tls_payload_remain -= chunk;
                    if (ctx->tls_payload_remain == 0) {
                        ctx->tls_in_payload = 0;
                        ctx->tls_hdr_len = 0;
                    }
                    continue;
                }

                /* Decrypt client data into cbuf */
                EVP_EncryptUpdate(ctx->c_dec, decrypted, &outl,
                                  raw + pos, chunk);
                if (outl > 0) {
                    ngx_memcpy(ctx->cbuf + ctx->cbuf_len, decrypted, outl);
                    ctx->cbuf_len += outl;
                }

                pos += chunk;
                ctx->tls_payload_remain -= chunk;

                if (ctx->tls_payload_remain == 0) {
                    ctx->tls_in_payload = 0;
                    ctx->tls_hdr_len = 0;
                }
                continue;
            }

            /* Accumulate TLS header bytes */
            if (ctx->tls_hdr_len < MTPROTO_TLS_HEADER_LEN) {
                ctx->tls_hdr[ctx->tls_hdr_len++] = raw[pos++];

                if (ctx->tls_hdr_len == MTPROTO_TLS_HEADER_LEN) {
                    /* Accept AppData (0x17) and CCS (0x14); skip others */
                    if (ctx->tls_hdr[0] != 0x17
                        && ctx->tls_hdr[0] != 0x14)
                    {
                        ngx_log_error(NGX_LOG_ERR, c->log, 0,
                                      "mtproto: unexpected TLS record type "
                                      "0x%02xd from client",
                                      ctx->tls_hdr[0]);
                        ngx_http_mtproto_close(ctx);
                        return;
                    }

                    ctx->tls_payload_remain =
                        (ctx->tls_hdr[3] << 8) | ctx->tls_hdr[4];
                    ctx->tls_in_payload = 1;
                }
                continue;
            }
        }

        /* Flush accumulated decrypted data to DC */
        if (ctx->cbuf_len > 0 && ctx->dc_conn) {
            rc = ngx_http_mtproto_flush_buf(ctx->dc_conn, ctx->cbuf,
                                             &ctx->cbuf_pos, &ctx->cbuf_len);
            if (rc == NGX_ERROR) {
                ngx_log_error(NGX_LOG_ERR, c->log, 0,
                              "mtproto: failed to send to DC");
                ngx_http_mtproto_close(ctx);
                return;
            }

            if (rc == NGX_AGAIN) {
                /* Backpressure: stop reading from client, arm DC write */
                if (ngx_handle_write_event(ctx->dc_conn->write, 0)
                    != NGX_OK)
                {
                    ngx_http_mtproto_close(ctx);
                    return;
                }
                break;
            }
        }
    }

    if (ngx_handle_read_event(rev, 0) != NGX_OK) {
        ngx_http_mtproto_close(ctx);
    }
}

/* ── DC → Client relay (read from DC) ─────────────────────────────────── */

static void
ngx_http_mtproto_dc_read_handler(ngx_event_t *rev)
{
    ngx_connection_t          *dc;
    ngx_http_mtproto_ctx_t    *ctx;
    ssize_t                    n;
    ngx_int_t                  rc;
    u_char                     raw[MTPROTO_RELAY_BUF];
    u_char                     encrypted[MTPROTO_RELAY_BUF];
    int                        outl;

    dc = rev->data;
    ctx = dc->data;

    if (ctx == NULL || ctx->state != MTPROTO_STATE_RELAY) {
        return;
    }

    if (rev->timedout) {
        ngx_log_error(NGX_LOG_INFO, dc->log, 0,
                      "mtproto: DC read timeout");
        ngx_http_mtproto_close(ctx);
        return;
    }

    /* If dbuf still has unsent data, try to flush first */
    if (ctx->dbuf_len > ctx->dbuf_pos) {
        rc = ngx_http_mtproto_flush_buf(ctx->client_conn, ctx->dbuf,
                                         &ctx->dbuf_pos, &ctx->dbuf_len);
        if (rc == NGX_ERROR) {
            ngx_http_mtproto_close(ctx);
            return;
        }

        if (rc == NGX_AGAIN) {
            /* Still blocked — keep write event armed, deactivate read */
            if (ngx_handle_write_event(ctx->client_conn->write, 0) != NGX_OK) {
                ngx_http_mtproto_close(ctx);
            }
            ngx_handle_read_event(rev, 0);
            return;
        }
    }

    /* Reset timeout */
    if (rev->timer_set) {
        ngx_del_timer(rev);
    }
    ngx_add_timer(rev, ctx->conf->timeout);

    for (;;) {
        n = dc->recv(dc, raw, sizeof(raw));

        if (n == NGX_AGAIN) {
            break;
        }

        if (n <= 0) {
            ngx_log_error(NGX_LOG_INFO, dc->log, 0,
                          "mtproto: DC disconnected");
            ngx_http_mtproto_close(ctx);
            return;
        }

        ngx_log_error(NGX_LOG_DEBUG, dc->log, 0,
                      "mtproto: DC sent %z bytes", n);

        /* DC data is plaintext — encrypt for client (obfs2) */
        EVP_EncryptUpdate(ctx->c_enc, encrypted, &outl, raw, n);

        /*
         * Wrap in TLS Application Data records into dbuf.
         * Split into chunks of max 16384 bytes.
         */
        size_t pos = 0;
        size_t total = outl;

        ctx->dbuf_pos = 0;
        ctx->dbuf_len = 0;

        while (pos < total) {
            size_t chunk = ngx_min(total - pos,
                                   (size_t) MTPROTO_TLS_MAX_PAYLOAD);

            ctx->dbuf[ctx->dbuf_len++] = 0x17;
            ctx->dbuf[ctx->dbuf_len++] = 0x03;
            ctx->dbuf[ctx->dbuf_len++] = 0x03;
            ctx->dbuf[ctx->dbuf_len++] = (chunk >> 8) & 0xff;
            ctx->dbuf[ctx->dbuf_len++] = chunk & 0xff;
            ngx_memcpy(ctx->dbuf + ctx->dbuf_len, encrypted + pos, chunk);
            ctx->dbuf_len += chunk;

            pos += chunk;
        }

        /* Flush framed data to client */
        if (ctx->dbuf_len > 0 && ctx->client_conn) {
            rc = ngx_http_mtproto_flush_buf(ctx->client_conn, ctx->dbuf,
                                             &ctx->dbuf_pos, &ctx->dbuf_len);
            if (rc == NGX_ERROR) {
                ngx_log_error(NGX_LOG_ERR, dc->log, 0,
                              "mtproto: failed to send to client");
                ngx_http_mtproto_close(ctx);
                return;
            }

            if (rc == NGX_AGAIN) {
                /* Backpressure: stop reading from DC, arm client write */
                if (ngx_handle_write_event(ctx->client_conn->write, 0)
                    != NGX_OK)
                {
                    ngx_http_mtproto_close(ctx);
                    return;
                }
                break;
            }
        }
    }

    if (ngx_handle_read_event(rev, 0) != NGX_OK) {
        ngx_http_mtproto_close(ctx);
    }
}

/* ── Write handlers: flush pending buffers and resume reads ────────────── */

static void
ngx_http_mtproto_client_write_handler(ngx_event_t *wev)
{
    ngx_connection_t          *c;
    ngx_http_mtproto_ctx_t    *ctx;
    ngx_int_t                  rc;

    c = wev->data;
    ctx = c->data;

    if (ctx == NULL || ctx->state != MTPROTO_STATE_RELAY) {
        return;
    }

    if (wev->timedout) {
        ngx_log_error(NGX_LOG_INFO, c->log, 0,
                      "mtproto: client write timeout");
        ngx_http_mtproto_close(ctx);
        return;
    }

    /* Flush dbuf (DC → client direction) */
    if (ctx->dbuf_len > ctx->dbuf_pos) {
        rc = ngx_http_mtproto_flush_buf(c, ctx->dbuf,
                                         &ctx->dbuf_pos, &ctx->dbuf_len);
        if (rc == NGX_ERROR) {
            ngx_http_mtproto_close(ctx);
            return;
        }

        if (rc == NGX_AGAIN) {
            /* Still blocked, re-arm write event */
            if (ngx_handle_write_event(wev, 0) != NGX_OK) {
                ngx_http_mtproto_close(ctx);
            }
            return;
        }

        /* Buffer flushed — resume reading from DC */
        if (ctx->dc_conn) {
            ngx_post_event(ctx->dc_conn->read, &ngx_posted_events);
        }
    }

    /*
     * No pending data — deactivate write event to prevent busy-looping.
     * On level-triggered (poll/select): active+ready causes deletion.
     * On edge-triggered (epoll/kqueue): harmless no-op (edge consumed).
     * Clear wev->ready so the read handler can re-arm via
     * ngx_handle_write_event() when backpressure occurs.
     */
    if (ngx_handle_write_event(wev, 0) != NGX_OK) {
        ngx_http_mtproto_close(ctx);
        return;
    }
    wev->ready = 0;
}

static void
ngx_http_mtproto_dc_write_handler(ngx_event_t *wev)
{
    ngx_connection_t          *dc;
    ngx_http_mtproto_ctx_t    *ctx;
    ngx_int_t                  rc;

    dc = wev->data;
    ctx = dc->data;

    if (ctx == NULL || ctx->state != MTPROTO_STATE_RELAY) {
        return;
    }

    if (wev->timedout) {
        ngx_log_error(NGX_LOG_INFO, dc->log, 0,
                      "mtproto: DC write timeout");
        ngx_http_mtproto_close(ctx);
        return;
    }

    /* Flush cbuf (client → DC direction) */
    if (ctx->cbuf_len > ctx->cbuf_pos) {
        rc = ngx_http_mtproto_flush_buf(dc, ctx->cbuf,
                                         &ctx->cbuf_pos, &ctx->cbuf_len);
        if (rc == NGX_ERROR) {
            ngx_http_mtproto_close(ctx);
            return;
        }

        if (rc == NGX_AGAIN) {
            /* Still blocked, re-arm write event */
            if (ngx_handle_write_event(wev, 0) != NGX_OK) {
                ngx_http_mtproto_close(ctx);
            }
            return;
        }

        /* Buffer flushed — resume reading from client */
        if (ctx->client_conn) {
            ngx_post_event(ctx->client_conn->read, &ngx_posted_events);
        }
    }

    /*
     * No pending data — deactivate write event to prevent busy-looping.
     * On level-triggered (poll/select): active+ready causes deletion.
     * On edge-triggered (epoll/kqueue): harmless no-op (edge consumed).
     * Clear wev->ready so the read handler can re-arm via
     * ngx_handle_write_event() when backpressure occurs.
     */
    if (ngx_handle_write_event(wev, 0) != NGX_OK) {
        ngx_http_mtproto_close(ctx);
        return;
    }
    wev->ready = 0;
}

/* ── Cleanup & close ──────────────────────────────────────────────────── */

static void
ngx_http_mtproto_close(ngx_http_mtproto_ctx_t *ctx)
{
    if (ctx->state == MTPROTO_STATE_DONE) {
        return;
    }

    ctx->state = MTPROTO_STATE_DONE;

    ngx_log_error(NGX_LOG_DEBUG,
                  ctx->client_conn ? ctx->client_conn->log : ngx_cycle->log,
                  0, "mtproto: closing connection");

    /* Close DC connection */
    if (ctx->dc_conn) {
        ngx_connection_t *dc = ctx->dc_conn;
        ctx->dc_conn = NULL;
        dc->data = NULL;

        if (dc->read->timer_set) {
            ngx_del_timer(dc->read);
        }
        if (dc->write->timer_set) {
            ngx_del_timer(dc->write);
        }
        ngx_close_connection(dc);
    }

    /* Close client connection */
    if (ctx->client_conn) {
        ngx_connection_t *c = ctx->client_conn;
        ctx->client_conn = NULL;
        c->data = NULL;

        if (c->read->timer_set) {
            ngx_del_timer(c->read);
        }
        if (c->write->timer_set) {
            ngx_del_timer(c->write);
        }
        ngx_close_connection(c);
    }

    /* Free crypto contexts */
    if (ctx->c_dec) { EVP_CIPHER_CTX_free(ctx->c_dec); ctx->c_dec = NULL; }
    if (ctx->c_enc) { EVP_CIPHER_CTX_free(ctx->c_enc); ctx->c_enc = NULL; }
    if (ctx->d_dec) { EVP_CIPHER_CTX_free(ctx->d_dec); ctx->d_dec = NULL; }
    if (ctx->d_enc) { EVP_CIPHER_CTX_free(ctx->d_enc); ctx->d_enc = NULL; }

    /* Destroy pool (frees all allocated memory including ctx itself) */
    if (ctx->pool) {
        ngx_pool_t *pool = ctx->pool;
        ctx->pool = NULL;
        ngx_destroy_pool(pool);
    }
}

static void
ngx_http_mtproto_cleanup(void *data)
{
    ngx_http_mtproto_ctx_t *ctx = data;

    if (ctx->state != MTPROTO_STATE_DONE) {
        /* Close DC connection only — client is being closed by pool destroy */
        if (ctx->dc_conn) {
            ngx_connection_t *dc = ctx->dc_conn;
            ctx->dc_conn = NULL;
            dc->data = NULL;
            if (dc->read->timer_set) {
                ngx_del_timer(dc->read);
            }
            if (dc->write->timer_set) {
                ngx_del_timer(dc->write);
            }
            ngx_close_connection(dc);
        }

        if (ctx->c_dec) { EVP_CIPHER_CTX_free(ctx->c_dec); ctx->c_dec = NULL; }
        if (ctx->c_enc) { EVP_CIPHER_CTX_free(ctx->c_enc); ctx->c_enc = NULL; }
        if (ctx->d_dec) { EVP_CIPHER_CTX_free(ctx->d_dec); ctx->d_dec = NULL; }
        if (ctx->d_enc) { EVP_CIPHER_CTX_free(ctx->d_enc); ctx->d_enc = NULL; }

        ctx->state = MTPROTO_STATE_DONE;
    }
}
