#ifndef __SIMPLE_HTTPS_H__
#define __SIMPLE_HTTPS_H__

#include "simple_http.h"
#include "simple_network.h"

int send_https_message(SSL *ssl, http_t *http);
int recv_https_message(SSL *ssl, http_t *http, FILE *fp);
int process_error(SSL *ssl, int ret);

#endif /* __SIMPLE_HTTPS_H__ */
