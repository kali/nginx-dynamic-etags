/* 
 *  Copyright (c) 2009 Mathieu Poumeyrol ( http://github.com/kali )
 *
 *  All rights reserved.
 *  All original code was written by Mike West ( http://mikewest.org/ ) and
        Adrian Jung ( http://me2day.net/kkung, kkungkkung@gmail.com ).
 *
 *  Copyright 2008 Mike West ( http://mikewest.org/ )
 *  Copyright 2009 Adrian Jung ( http://me2day.net/kkung, kkungkkung@gmail.com ).
 *
 *  The following is released under the Creative Commons BSD license,
 *  available for your perusal at `http://creativecommons.org/licenses/BSD/`
 */
#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include <ngx_md5.h>
#include <sys/stat.h>

typedef struct {
    ngx_flag_t  enable;
} ngx_http_dynamic_etags_loc_conf_t;

typedef struct {
    ngx_flag_t done;
} ngx_http_dynamic_etags_module_ctx_t;

static ngx_http_output_header_filter_pt  ngx_http_next_header_filter;
static ngx_http_output_body_filter_pt    ngx_http_next_body_filter;

static void * ngx_http_dynamic_etags_create_loc_conf(ngx_conf_t *cf);
static char * ngx_http_dynamic_etags_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child);
static ngx_int_t ngx_http_dynamic_etags_init(ngx_conf_t *cf);
static ngx_int_t ngx_http_dynamic_etags_header_filter(ngx_http_request_t *r);
static ngx_int_t ngx_http_dynamic_etags_body_filter(ngx_http_request_t *r, ngx_chain_t *in);

static ngx_command_t  ngx_http_dynamic_etags_commands[] = {
    { ngx_string( "dynamic_etags" ),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof( ngx_http_dynamic_etags_loc_conf_t, enable ),
      NULL },
      ngx_null_command
};

static ngx_http_module_t  ngx_http_dynamic_etags_module_ctx = {
    NULL,                                   /* preconfiguration */
    ngx_http_dynamic_etags_init,             /* postconfiguration */

    NULL,                                   /* create main configuration */
    NULL,                                   /* init main configuration */

    NULL,                                   /* create server configuration */
    NULL,                                   /* merge server configuration */

    ngx_http_dynamic_etags_create_loc_conf,  /* create location configuration */
    ngx_http_dynamic_etags_merge_loc_conf,   /* merge location configuration */
};

ngx_module_t  ngx_http_dynamic_etags_module = {
    NGX_MODULE_V1,
    &ngx_http_dynamic_etags_module_ctx,  /* module context */
    ngx_http_dynamic_etags_commands,     /* module directives */
    NGX_HTTP_MODULE,                    /* module type */
    NULL,                               /* init master */
    NULL,                               /* init module */
    NULL,                               /* init process */
    NULL,                               /* init thread */
    NULL,                               /* exit thread */
    NULL,                               /* exit process */
    NULL,                               /* exit master */
    NGX_MODULE_V1_PADDING
};

static void * ngx_http_dynamic_etags_create_loc_conf(ngx_conf_t *cf) {
    ngx_http_dynamic_etags_loc_conf_t    *conf;

    conf = ngx_pcalloc( cf->pool, sizeof( ngx_http_dynamic_etags_loc_conf_t ) );
    if ( NULL == conf ) {
        return NGX_CONF_ERROR;
    }
    conf->enable   = NGX_CONF_UNSET_UINT;
    return conf;
}

static char * ngx_http_dynamic_etags_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child) {
    ngx_http_dynamic_etags_loc_conf_t *prev = parent;
    ngx_http_dynamic_etags_loc_conf_t *conf = child;

    ngx_conf_merge_value( conf->enable, prev->enable, 0 );

    return NGX_CONF_OK;
}

static ngx_int_t ngx_http_dynamic_etags_init(ngx_conf_t *cf) {
    ngx_http_next_header_filter = ngx_http_top_header_filter;
    ngx_http_top_header_filter = ngx_http_dynamic_etags_header_filter;

    ngx_http_next_body_filter = ngx_http_top_body_filter;
    ngx_http_top_body_filter = ngx_http_dynamic_etags_body_filter;

    return NGX_OK;
}

static ngx_int_t ngx_http_dynamic_etags_header_filter(ngx_http_request_t *r) {

    ngx_http_dynamic_etags_module_ctx_t       *ctx;

    ctx = ngx_http_get_module_ctx(r, ngx_http_dynamic_etags_module);

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "HEADER FILTER ctx=%p", ctx);
    if (ctx) {
        return ngx_http_next_header_filter(r);
    }

    ctx = ngx_pcalloc(r->pool, sizeof(ngx_http_dynamic_etags_module_ctx_t));
    if (ctx == NULL) {
        return NGX_ERROR;
    }

    ngx_http_set_ctx(r, ctx, ngx_http_dynamic_etags_module);

    ngx_http_clear_content_length(r);
    ngx_http_clear_accept_ranges(r);

    r->main_filter_need_in_memory = 1;
    r->filter_need_in_memory = 1;

    return NGX_OK;
}

static u_char hex[] = "0123456789abcdef";

static ngx_int_t ngx_http_dynamic_etags_body_filter(ngx_http_request_t *r, ngx_chain_t *in) {
    ngx_chain_t *chain_link;
    ngx_http_dynamic_etags_module_ctx_t       *ctx;

    ngx_int_t  rc;
    ngx_md5_t md5;
    unsigned char digest[16];
    ngx_uint_t i;

    ctx = ngx_http_get_module_ctx(r, ngx_http_dynamic_etags_module);
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "BODY FILTER ctx=%p", ctx);

    ctx = ngx_http_get_module_ctx(r, ngx_http_dynamic_etags_module);
    if (ctx == NULL) {
        return ngx_http_next_body_filter(r, in);
    }

    ngx_md5_init(&md5);
    for (chain_link = in; chain_link; chain_link = chain_link->next) {
    ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "hashing %p, %p", chain_link->buf->last, chain_link->buf->pos);
        ngx_md5_update(&md5, chain_link->buf->pos,
            chain_link->buf->last - chain_link->buf->pos);
    }
    ngx_md5_final(digest, &md5);

    unsigned char* etag = ngx_pcalloc(r->pool, 34);
    etag[0] = etag[33] = '"';
    for ( i = 0 ; i < 16; i++ ) {
        etag[2*i+1] = hex[digest[i] >> 4];
        etag[2*i+2] = hex[digest[i] & 0xf];
    }

    r->headers_out.etag->hash = 1;
    r->headers_out.etag->key.len = sizeof("ETag") - 1;
    r->headers_out.etag->key.data = (u_char *) "ETag";
    r->headers_out.etag->value.len = 34;
    r->headers_out.etag->value.data = etag;

    /* look for If-None-Match in request headers */
    ngx_uint_t      found=0;
    ngx_list_part_t *part = NULL;
    ngx_table_elt_t *header = NULL;
    ngx_table_elt_t if_none_match;
    part = &r->headers_in.headers.part;
    header = part->elts;
    for ( i = 0 ; ; i++ ) {
        if ( i >= part->nelts) {
            if ( part->next == NULL ) {
                    break;
            }

            part = part->next;
            header = part->elts;
            i = 0;
        }

        ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0 , "[Etag] Header %V: %V", &header[i].key, &header[i].value );

        if ( ngx_strcmp(header[i].key.data, "If-None-Match") == 0 ) {
            if_none_match = header[i];
            found = 1;
            break;
        }
    }

    if ( found ) {
        if ( ngx_strncmp(r->headers_out.etag->value.data, if_none_match.value.data, r->headers_out.etag->value.len) == 0 ) {

            r->headers_out.status = NGX_HTTP_NOT_MODIFIED;
            r->headers_out.status_line.len = 0;
            r->headers_out.content_type.len = 0;
            ngx_http_clear_content_length(r);
            ngx_http_clear_accept_ranges(r);
        }
    }

    rc = ngx_http_next_header_filter(r);
    if (rc == NGX_ERROR || rc > NGX_OK) {
        return NGX_ERROR;
    }

    ngx_http_set_ctx(r, NULL, ngx_http_dynamic_etags_module);

    return ngx_http_next_body_filter(r, in);
}
