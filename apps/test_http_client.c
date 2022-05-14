#include <openssl/ssl.h>
#include <openssl/err.h>
#include <errno.h>
#include <dpi/debug.h>
#include <simple_http/simple_https.h>
#include <getopt.h>
#include <stdlib.h>
#include <unistd.h>

#include "errors.h"

int dtype;

int usage(const char *pname)
{
  emsg(">> Usage: %s [options]", pname);
  emsg("Options");
  emsg("  -d, --domain      Server Domain Name");
  emsg("  -p, --port        Server Port Number");
  emsg("  -a, --cacert      CA Certificate");
  emsg("  -r, --rname       Request File Name (default: index.html)");
  emsg("  -f, --fname       Downloaded File Name (default: requested file name)");
  exit(1);
}

int main(int argc, char *argv[])
{
  http_t *req, *resp;
  SSL_CTX *ctx;
  SSL_METHOD *method;
  SSL *ssl;

  int c, sock, err, port, ret, rset;
  char *key, *value;
  const char *pname, *fname, *cacert, *rname;
  const char *domain;
  unsigned char abs_path[256] = {0, };
  FILE *fp;

  dtype = DPI_DEBUG_CLIENT|DPI_DEBUG_LIBRARY;
  pname = argv[0];
  domain = NULL;
  cacert = NULL;
  port = -1;
  rname = "index.html";
  fname = rname;
  err = 0;
  rset = 0;

  while (1)
  {
    int option_index = 0;
    static struct option long_options[] = {
      {"domain", required_argument, 0, 'd'},
      {"port", required_argument, 0, 'p'},
      {"cacert", required_argument, 0, 'a'},
      {"rname", required_argument, 0, 'r'},
      {"fname", required_argument, 0, 'f'},
      {0, 0, 0, 0}
    };

    const char *opt = "d:p:a:r:f:0";

    c = getopt_long(argc, argv, opt, long_options, &option_index);

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

      case 'a':
        cacert = optarg;
        if (access(cacert, F_OK) == -1)
          err |= ERR_INVALID_CA_CERTIFICATE_PATH;
        break;

      case 'r':
        rname = optarg;
        rset = 1;
        break;

      case 'f':
        fname = optarg;
        break;

      default:
        usage(pname);
    }
  }

  if (!domain)
  {
    emsg("Please specify the domain name of the server to connect");
    usage(pname);
  }

  if (!cacert)
  {
    emsg("Please specify the path of the CA certificate file");
    usage(pname);
  }

  if (port < 0)
  {
    emsg("Please specify the port number of the server to connect");
    usage(pname);
  }

  if (err)
  {
    if (err & ERR_INVALID_CA_CERTIFICATE_PATH)
    {
      emsg("Invalid CA certificate path: %s", cacert);
    }

    usage(pname);
  }

  fp = fopen(fname, "w");
  SSL_load_error_strings();
  init_http_module();

  req = init_http_message(HTTP_TYPE_REQUEST);
  if (!req) goto err;

  http_set_version(req, HTTP_VERSION_1_1);
  http_set_method(req, HTTP_METHOD_GET);
  http_set_domain(req, domain, (int) strlen(domain));
  http_set_default_attributes(req);

  if (rset)
    snprintf(abs_path, strlen(rname) + 2, "/%s", rname);
  else
    abs_path[0] = '/';
  printf("abs_path: %s\n", abs_path);
  http_set_abs_path(req, abs_path, (int) strlen(abs_path));

  key = "Accept-Encoding";
  value = "gzip, deflate";
  add_header_attribute(req, key, (int) strlen(key), value, (int) strlen(value));

  print_header(req);

  del_header_attribute(req, key, (int) strlen(key));

  print_header(req);

  method = (SSL_METHOD *)TLS_client_method();
  ctx = SSL_CTX_new(method);

  if (SSL_CTX_load_verify_locations(ctx, cacert, NULL) != 1)
  {
    emsg("SSL_CTX_load_verify_locations() error");
    ERR_print_errors_fp(stderr);
    goto err;
  }

  ssl = SSL_new(ctx);

  sock = open_connection(domain, port, 1);
  if (sock < 0)
    abort();
  SSL_set_fd(ssl, sock);
  SSL_set_connect_state(ssl);

  while (!err)
  {
    ret = SSL_do_handshake(ssl);
    err = process_error(ssl, ret);

    if (err < 0)
      abort();
  }
  dmsg(DPI_DEBUG_CLIENT, "TLS session is established with %s", SSL_get_cipher(ssl));

  ret = HTTP_NOT_FINISHED;
  while (ret == HTTP_NOT_FINISHED)
    ret = send_https_message(ssl, req);

  if (ret != HTTP_SUCCESS) goto err;

  resp = init_http_message(HTTP_TYPE_RESPONSE);
  if (!resp) goto err;

  ret = HTTP_NOT_FINISHED;
  while (ret == HTTP_NOT_FINISHED)
    ret = recv_https_message(ssl, resp, fp);
  if (ret != HTTP_SUCCESS) goto err;

  print_header(resp);

err:
  if (ssl)
    SSL_free(ssl);

  if (ctx)
    SSL_CTX_free(ctx);

  return 0;
}
