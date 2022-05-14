#include <stdio.h>
#include <errno.h>
#include <unistd.h>
#include <malloc.h>
#include <string.h>
#include <time.h>
#include <resolv.h>
#include <netdb.h>
#include <pthread.h>
#include <errno.h>
#include <limits.h>
#include <getopt.h>
#include <assert.h>

#include <sys/time.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>

#include <openssl/ssl.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include "errors.h"

#include <dpi/debug.h>
#include <dpi/defines.h>
#include <simple_http/simple_https.h>

#define DEFAULT_DOMAIN_NAME "www.mt-dpi.com"
#define DEFAULT_PORT_NUMBER 5556

typedef struct arg_st
{
  const char *domain;
  int port;
  const char *content;
  int mtdpi;
  int blindbox;
  int resumption;
  
  SSL_CTX *ctx;
} arg_t;

void *run(void *data);
SSL_CTX* init_client_ctx(void);
void load_ecdh_params(SSL_CTX *ctx);
unsigned long get_current_time(void);
unsigned long get_current_cpu(void);

int http_make_request(uint8_t *domain, uint32_t dlen, uint8_t *content,
		uint32_t clen, uint8_t *msg, uint32_t *mlen);
int http_parse_response(uint8_t *msg, uint32_t mlen);

int usage(const char *pname)
{
  emsg(">> Usage: %s [options]", pname);
  emsg("Options");
  emsg("  -d, --domain      Server Domain Name");
  emsg("  -p, --port        Server Port Number");
  emsg("  -c, --content     Request Content Name (default: index.html)");
  emsg("  -r, --resumption  Enable Session Resumption");
  emsg("  -m, --mtdpi       Enable MT-DPI");
  emsg("  -b, --blindbox    Enable Blindbox");
  exit(1);
}

int dtype;
int main(int argc, char *argv[])
{   
  const char *pname, *domain, *content, *opt;
	int c, rc, port, mtdpi, blindbox, resumption;
  SSL_CTX *ctx;
  arg_t *arg;

  dtype = DPI_DEBUG_CLIENT|DPI_DEBUG_LIBRARY;
  pname = argv[0];
  domain = DEFAULT_DOMAIN_NAME;
  content = NULL;
  port = DEFAULT_PORT_NUMBER;
  resumption = 0;
  mtdpi = 0;
  blindbox = 0;

  while (1)
  {
    int opt_idx = 0;
    static struct option long_options[] = {
      {"domain", required_argument, 0, 'd'},
      {"port", required_argument, 0, 'p'},
      {"content", required_argument, 0, 'c'},
      {"resumption", no_argument, 0, 'r'},
      {"mtdpi", no_argument, 0, 'm'},
      {"blindbox", no_argument, 0, 'b'},
      {0, 0, 0, 0}
    };

    opt = "d:p:c:rmb0";

    c = getopt_long(argc, argv, opt, long_options, &opt_idx);

    if (c == -1)
      break;

    switch (c)
    {
      case 'd':
        domain = optarg;
        break;
      case 'p':
        port = atoi(optarg);
        break;
      case 'c':
        content = optarg;
        break;
      case 'r':
        resumption = 1;
        break;
      case 'm':
        mtdpi = 1;
        break;
      case 'b':
        blindbox = 1;
        break;
      default:
        usage(pname);
    }
  }
  
  if (domain)
  {
    imsg(DPI_DEBUG_CLIENT, "Host: %s", domain);
  }

  assert(port > 0 && port < 65536);
  imsg(DPI_DEBUG_CLIENT, "Port: %d", port);

  if (content)
  {
    imsg(DPI_DEBUG_CLIENT, "Content: %s", content);
  }
  else
  {
    content = "index.html";
  }

  imsg(DPI_DEBUG_CLIENT, "Resumption: %d", resumption);
  imsg(DPI_DEBUG_CLIENT, "MT-DPI: %d", mtdpi);
  imsg(DPI_DEBUG_CLIENT, "Blindbox: %d", blindbox);

  if (mtdpi == 1 && blindbox == 1)
  {
    emsg("MT-DPI and Blindbox should not be enabled simultaneously");
    usage(pname);
  }

	pthread_t thread;
	pthread_attr_t attr;
	pthread_attr_init(&attr);
	pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_JOINABLE);
	void *status;

  arg = (arg_t *)malloc(sizeof(arg_t));

	ctx = init_client_ctx();
	load_ecdh_params(ctx);

  arg->domain = domain;
  arg->port = port;
  arg->content = content;
  arg->ctx = ctx;
  arg->resumption = resumption;
  arg->mtdpi = mtdpi;
  arg->blindbox = blindbox;

  rc = pthread_create(&thread, &attr, run, arg);
	if (rc) {
		emsg("return code from pthread_create: %d", rc);
		return 1;
	}

	pthread_attr_destroy(&attr);
	rc = pthread_join(thread, &status);
	if (rc) {
		emsg("return code from pthread_join: %d", rc);
		return 1;
	}

	SSL_CTX_free(ctx); /* release context */

	return 0;
}

void *run(void *data)
{	
	int ret, err, server, length, len, tbr, rcvd, offset, shut;
	SSL *ssl;
  SSL_SESSION *session;
  arg_t *arg;
  http_t *req, *resp;
  uint8_t *p;
  uint8_t rbuf[BUF_SIZE] = {0, };
  unsigned long tstart, tmid, tend, cstart, cend;

  arg = (arg_t *)data;
  session = NULL;
  req = resp = NULL;

  ssl = SSL_new(arg->ctx);   
  SSL_set_tlsext_host_name(ssl, arg->domain);

  if (arg->mtdpi)
    SSL_enable_mt_dpi(ssl);

  if (arg->blindbox)
    SSL_enable_blindbox(ssl);

  if (arg->content)
  {
    req = init_http_message(HTTP_TYPE_REQUEST);
    if (!req)
    {
      emsg("http request error");
      goto err;
    }

    http_set_version(req, HTTP_VERSION_1_1);
    http_set_method(req, HTTP_METHOD_GET);
    http_set_domain(req, arg->domain, strlen(arg->domain));
    http_set_default_attributes(req);
    http_set_abs_path(req, arg->content, strlen(arg->content));

    print_header(req);

    resp = init_http_message(HTTP_TYPE_RESPONSE);
    if (!resp)
    {
      emsg("http response error");
      goto err;
    }
  }

	server = open_connection(arg->domain, arg->port, 1);
  SSL_set_fd(ssl, server);

  if (session != NULL)
    SSL_set_session(ssl, session);

  while (!err)
  {
    ret = SSL_connect(ssl);
    err = process_error(ssl, ret);

    if (err < 0)
    {
      emsg("Failed to SSL connect()");
      ERR_print_errors_fp(stderr);
      goto err;
    }
  }
  imsg(DPI_DEBUG_CLIENT, "TLS session is established with %s", SSL_get_cipher(ssl));
  printf("TLS session is established with %s\n", SSL_get_cipher(ssl));

  sleep(1);
  printf("Now we send the HTTPS GET request\n");
  if (arg->content)
  {
    tstart = get_current_time();
    ret = HTTP_NOT_FINISHED;
    while (ret == HTTP_NOT_FINISHED)
      ret = send_https_message(ssl, req);
    tmid = get_current_time();


    if (ret != HTTP_SUCCESS)
    {
      emsg("Send http request error");
      goto err;
    }

    tbr = 4;
    offset = 0;
    while (offset < tbr)
    {
      rcvd = SSL_read(ssl, rbuf+offset, tbr-offset);
      if (rcvd > 0)
        offset += rcvd;
    }
    assert(offset == tbr);

    p = rbuf;
    PTR_TO_VAR_4BYTES(p, length);

    tbr = length;
    offset = 0;
    while (offset < tbr)
    {
      if ((tbr - offset) < BUF_SIZE)
        len = (tbr - offset);
      else
        len = BUF_SIZE;
      rcvd = SSL_read(ssl, rbuf, len);
      if (rcvd > 0)
        offset += rcvd;
    }
    assert(offset == tbr);
    tend = get_current_time();
    imsg(DPI_DEBUG_SERVER, "Send Time: %lu ns", tmid - tstart);
    imsg(DPI_DEBUG_SERVER, "Elapsed Time: %lu ns", tend - tstart);
    imsg(DPI_DEBUG_SERVER, "CPU Time: %lu ns", cend - cstart);

    printf("Received: %d bytes\n", length);
  }
    
  sleep(0.5);

err: 
	if (ssl) {
		//SSL_free(ssl);
		ssl = NULL;
	}
	if (server != -1)
  {
		close(server);
  }

	return NULL;
}

SSL_CTX* init_client_ctx(void) {
	SSL_METHOD *method;
	SSL_CTX *ctx;

	SSL_load_error_strings();
	method = (SSL_METHOD *) TLS_client_method();
	ctx = SSL_CTX_new(method);

	if (ctx == NULL) {
		ERR_print_errors_fp(stderr);
		abort();
	}

  SSL_CTX_set_max_proto_version(ctx, TLS1_3_VERSION);
	SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION);
	SSL_CTX_set_verify_depth(ctx, 4);
	SSL_CTX_set_ciphersuites(ctx, "TLS_AES_128_GCM_SHA256:TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256");

	return ctx;
}

void load_ecdh_params(SSL_CTX *ctx) {
	EC_KEY *ecdh;
	ecdh = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);

	if (!ecdh)
		perror("Couldn't load the ec key");

	if (SSL_CTX_set_tmp_ecdh(ctx, ecdh) != 1)
		perror("Couldn't set the ECDH parameter (NID_X9_62_prime256v1)");
}

unsigned long get_current_time(void)
{
  struct timespec ts;
  clock_gettime(CLOCK_MONOTONIC, &ts);
  return ts.tv_sec * 1000000000 + ts.tv_nsec;
}

unsigned long get_current_cpu(void)
{
  struct timespec tp;
  clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &tp);
  return tp.tv_sec * 1000000000 + tp.tv_nsec;
}

