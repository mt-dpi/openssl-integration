#ifndef __SIMPLE_NETWORK_H__
#define __SIMPLE_NETWORK_H__

#include <resolv.h>
#include <sys/socket.h>
#include <netdb.h>
#include <openssl/ssl.h>

#define TIME_OUT 10000

int send_tcp_message(int fd, uint8_t *buf, int len);
int recv_tcp_message(int fd, uint8_t *buf, int max);

int send_tls_message(SSL *ssl, uint8_t *buf, int len);
int recv_tls_message(SSL *ssl, uint8_t *buf, int max);

int open_connection(const char *domain, uint16_t port, int nonblock);
int open_listener(uint16_t port, int nonblock);

#endif /* __SIMPLE_SOCKET_H__ */
