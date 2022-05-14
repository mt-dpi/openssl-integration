#ifndef __SIMPLE_HTTP_CALLBACKS_H__
#define __SIMPLE_HTTP_CALLBACKS_H__

#include "simple_https.h"

typedef struct http_cb_st {
  int method;
  char *abs_path;
  int alen;
  int (*callback)(http_t *req, http_t *resp);
  struct http_cb_st *next;
} http_cb_t;

typedef struct http_cbs_st {
  int num_of_cbs;
  http_cb_t *head;
} http_cbs_t;

http_cbs_t *init_http_callbacks(void);
int register_callback(http_cbs_t *cbs, int method, char *abs_path, int alen,
    int (*callback)(http_t *req, http_t *resp));
int process_request(http_cbs_t *cbs, http_t *req, http_t *resp);
void print_callbacks(http_cbs_t *cbs);

#endif /* __SIMPLE_HTTP_CALLBACKS_H__ */
