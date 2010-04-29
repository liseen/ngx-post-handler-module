#ifndef NGX_HTTP_PROTOHANDLER_MODULE_H
#define NGX_HTTP_PROTOHANDLER_MODULE_H

#include <ngx_core.h>
#include <ngx_http.h>
#include <nginx.h>

#include "post_handler.h"

typedef struct {
    ngx_str_t   ph_module_name;
    ngx_str_t   ph_config_file;

    void *ph_handler;
    post_handler_worker_t *ph_worker;
} ngx_http_post_handler_loc_conf_t;

typedef struct {
    ngx_http_request_t        *request;
    ngx_int_t   read_okay;
} ngx_http_post_handler_ctx_t;

extern ngx_module_t  ngx_http_post_handler_module;

#endif
