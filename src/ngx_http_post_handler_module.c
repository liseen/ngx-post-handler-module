#define DDEBUG 0
#include "ddebug.h"

/*
 * Copyright (C) taobao/nanyu
 */

#include <dlfcn.h>

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include <nginx.h>
//#include <unistd.h>

#include "ngx_http_post_handler_module.h"
#include "post_handler.h"

static void *ngx_http_post_handler_create_loc_conf(ngx_conf_t *cf);

static char *ngx_http_post_handler_module_name(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);

static ngx_int_t ngx_http_post_handler_init(ngx_conf_t* cf);

static ngx_int_t ngx_http_post_handler_init_ctx(ngx_http_request_t *r, ngx_http_post_handler_ctx_t **ctx_ptr);
static ngx_int_t ngx_http_post_handler_handler(ngx_http_request_t *r);

static ngx_int_t ngx_http_post_handler_exec_read_request_body(ngx_http_request_t* r, ngx_http_post_handler_ctx_t *ctx);
static void ngx_http_post_handler_post_read_request_body(ngx_http_request_t *r);
static ngx_str_t ngx_http_post_handler_get_requst_body(ngx_http_request_t *r);

static ngx_command_t ngx_http_post_handler_commands[] = {
    {
        ngx_string("post_handler"),
        NGX_HTTP_LOC_CONF|NGX_CONF_TAKE2,
        ngx_http_post_handler_module_name,
        //ngx_conf_set_str_slot,
        NGX_HTTP_LOC_CONF_OFFSET,
        offsetof(ngx_http_post_handler_loc_conf_t, ph_module_name),
        NULL
    },

    ngx_null_command
};

static ngx_http_module_t  ngx_http_post_handler_module_ctx = {
    NULL,                          /* preconfiguration */
    ngx_http_post_handler_init,         /* postconfiguration */

    NULL,                          /* create main configuration */
    NULL,                          /* init main configuration */

    NULL,                          /* create server configuration */
    NULL,                          /* merge server configuration */

    ngx_http_post_handler_create_loc_conf,                          /* create location configuration */
    NULL                           /* merge location configuration */
};

ngx_module_t ngx_http_post_handler_module = {
    NGX_MODULE_V1,
    &ngx_http_post_handler_module_ctx, /* module context */
    ngx_http_post_handler_commands,    /* module directives */
    NGX_HTTP_MODULE,               /* module type */
    NULL,                          /* init master */
    NULL,                          /* init module */
    NULL,                          /* init process */
    NULL,                          /* init thread */
    NULL,                          /* exit thread */
    NULL,                          /* exit process */
    NULL,                          /* exit master */
    NGX_MODULE_V1_PADDING
};

static void *
ngx_http_post_handler_create_loc_conf(ngx_conf_t *cf) {
    DD("create loc conf");
    ngx_http_post_handler_loc_conf_t *conf;
    conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_post_handler_loc_conf_t));
    if (conf == NULL) {
        return NGX_CONF_ERROR;
    }
    DD("create loc conf okay");
    return conf;
}

static char *ngx_http_post_handler_module_name(ngx_conf_t *cf, ngx_command_t *cmd, void *conf) {
    ngx_http_core_loc_conf_t  *clcf;
    ngx_http_post_handler_loc_conf_t  *olcf;
    char so_name[MAX_SO_NAME];

    void *dl_lib = NULL;
    void *post_handler_worker;
    void *post_handler_handler;
    char *error;

    ngx_str_t *raw_args;

    // init handler
    clcf = ngx_http_conf_get_module_loc_conf(cf, ngx_http_core_module);
    clcf->handler = ngx_http_post_handler_handler;

    // init post_handler module name
    //post_handler_module_name = (ngx_str_t*)((u_char*)conf + cmd->offset);
    olcf = (ngx_http_post_handler_loc_conf_t *)conf;

    raw_args = cf->args->elts;
    olcf->ph_module_name = raw_args[1];
    olcf->ph_config_file = raw_args[2];

    DD("module name: %s", olcf->ph_module_name.data);
    DD("config file: %s", olcf->ph_config_file.data);

    snprintf(so_name, MAX_SO_NAME, "lib%s.so", olcf->ph_module_name.data);

    dl_lib = dlopen (so_name, RTLD_NOW);
    if (!dl_lib) {
        fprintf(stderr, "%s\n", dlerror());
        return NGX_CONF_ERROR;
    }
    dlerror();    /* Clear any existing error */

    post_handler_worker = dlsym(dl_lib, (char *) olcf->ph_module_name.data);
    if ((error = dlerror()) != NULL)  {
        fprintf(stderr, "%s\n", dlerror());
        return NGX_CONF_ERROR;
    }

    olcf->ph_worker = (post_handler_worker_t *)post_handler_worker;

    DD("begin init handler");
    //fprintf(stderr, "init handler pid: %d\n", (int)getpid());
    // init config file
    post_handler_handler = olcf->ph_worker->init((char*)olcf->ph_config_file.data);
    //post_handler_handler = olcf->ph_worker->init("fadd");

    if (!post_handler_handler) {
        return NGX_CONF_ERROR;
    }
    DD("end init handler");

    olcf->ph_handler = post_handler_handler;

    return NGX_CONF_OK;
}

static ngx_int_t
ngx_http_post_handler_init(ngx_conf_t *cf)
{
    DD("post_handler init");
/*
    ngx_http_core_loc_conf_t  *clcf;

    clcf = ngx_http_conf_get_module_loc_conf(cf, ngx_http_core_module);
    clcf->handler = ngx_http_post_handler_handler;
*/
    return NGX_OK;
}

ngx_int_t
ngx_http_post_handler_init_ctx(ngx_http_request_t *r, ngx_http_post_handler_ctx_t **ctx_ptr) {
    ngx_http_post_handler_ctx_t         *ctx;

    *ctx_ptr = ngx_pcalloc(r->pool, sizeof(ngx_http_post_handler_ctx_t));
    if (*ctx_ptr == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    ctx = *ctx_ptr;

    ctx->read_okay = 0;

    return NGX_OK;
}


static ngx_str_t
ngx_http_post_handler_get_requst_body(ngx_http_request_t *r) {
    u_char       *p;
    u_char       *data;
    size_t        len;
    ngx_buf_t    *buf, *next;
    ngx_chain_t  *cl;
    ngx_str_t    body = ngx_null_string;

    DD("get request body");
    if (r->request_body == NULL
        || r->request_body->bufs == NULL
        || r->request_body->temp_file) {
        return body;
    } else {
        cl = r->request_body->bufs;
        buf = cl->buf;

        if (cl->next == NULL) {
            len = (buf->last - buf->pos);
            DD("get request body size: %d", (int)len);
            p = ngx_pnalloc(r->pool, len + 1);
            if (p == NULL) {
                return body;
            }
            data = p;
            ngx_memcpy(p, buf->pos, len);
            data[len] = 0;

            DD("ngx_cpymeme: %s", p);
        } else {
            DD("has next buf request body");
            next = cl->next->buf;
            len = (buf->last - buf->pos) + (next->last - next->pos);
            p = ngx_pnalloc(r->pool, len + 1);
            data = p;
            if (p == NULL) {
                return body;
            }
            p = ngx_cpymem(p, buf->pos, buf->last - buf->pos);
            ngx_memcpy(p, next->pos, next->last - next->pos);
            data[len] = 0;
        }
    }

    body.len = len;
    body.data = data;

    return  body;
}

static ngx_int_t
ngx_http_post_handler_handler(ngx_http_request_t *r)
{
    DD("handler request");
    ngx_http_post_handler_loc_conf_t    *olcf;
    ngx_http_post_handler_ctx_t         *ctx;

    ngx_int_t    rc;
    ngx_buf_t    *b;
    ngx_chain_t   out;

    ngx_str_t   input;
    u_char       *output_str = NULL;
    u_char       *output = NULL;
    size_t       output_len = 0;

    olcf = ngx_http_get_module_loc_conf(r, ngx_http_post_handler_module);
    if (olcf == NULL) {
        return NGX_DECLINED;
    }

    ctx = ngx_http_get_module_ctx(r, ngx_http_post_handler_module);
    if (ctx == NULL) {
        rc = ngx_http_post_handler_init_ctx(r, &ctx);
        if (rc != NGX_OK) {
            return NGX_DECLINED;
            //return rc;
        }

        ngx_http_set_ctx(r, ctx, ngx_http_post_handler_module);
    }

    if (! ctx->read_okay) {
        return ngx_http_post_handler_exec_read_request_body(r, ctx);
    }

    // get input request body
    input = ngx_http_post_handler_get_requst_body(r);
    DD("after get input request body");
    if (input.len == 0) {
        return NGX_DECLINED;
    }

    //fprintf(stderr, "process handler pid: %d\n", (int)getpid());
    output = (u_char *)olcf->ph_worker->process(olcf->ph_handler, (char *)input.data);

    if (output == NULL) {
        return NGX_DECLINED;
    }

    output_len = ngx_strlen(output);

    output_str = ngx_pnalloc(r->pool, output_len + 1);
    if (output_str == NULL) {
        return NGX_DECLINED;
    }
    ngx_memcpy(output_str, output, output_len);
    output_str[output_len] = 0;

    if (olcf->ph_worker->free_output) {
        olcf->ph_worker->free_output((char *)output);
    }

    b = ngx_pcalloc(r->pool, sizeof(ngx_buf_t));
    out.buf = b;
    out.next = NULL;

    //b->pos = output_str.data;
    b->pos = output_str;
    b->last = output_str + output_len;
    b->memory = 1;
    b->last_buf = 1;

    // output header
    r->headers_out.content_type.len = sizeof("text/plain") - 1;
    r->headers_out.content_type.data = (u_char *) "text/plain";
    r->headers_out.status = NGX_HTTP_OK;
    //r->headers_out.content_length_n = olcf->post_handler_module_name.len;
    r->headers_out.content_length_n = output_len;
    ngx_http_send_header(r);

    return ngx_http_output_filter(r, &out);
}

static ngx_int_t
ngx_http_post_handler_exec_read_request_body(
        ngx_http_request_t* r, ngx_http_post_handler_ctx_t *ctx) {
    ngx_int_t           rc;

    DD("ngx_http_post_handler_exec_read_request_body");

    rc = ngx_http_read_client_request_body(r, ngx_http_post_handler_post_read_request_body);
    if (rc >= NGX_HTTP_SPECIAL_RESPONSE) {
        return rc;
    }
    return NGX_DONE;
}

static void
ngx_http_post_handler_post_read_request_body(ngx_http_request_t *r) {
    ngx_http_post_handler_ctx_t         *ctx;

    DD("ngx_http_post_handler_post_read_request_body");

    ctx = ngx_http_get_module_ctx(r, ngx_http_post_handler_module);
    if (ctx == NULL) {
        return ngx_http_finalize_request(r, NGX_HTTP_INTERNAL_SERVER_ERROR);
    }

    ctx->read_okay = 1;
    ngx_http_finalize_request(r, ngx_http_post_handler_handler(r));
}


