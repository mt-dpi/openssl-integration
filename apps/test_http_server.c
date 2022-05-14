#include <openssl/ssl.h>
#include <openssl/err.h>
#include <errno.h>
#include <unistd.h>
#include <getopt.h>

#include <dpi/debug.h>
#include <simple_http/simple_https.h>
#include <simple_http/simple_http_callbacks.h>

#include "errors.h"

int dtype;

int process_index(http_t *req, http_t *resp);
int process_json(http_t *req, http_t *resp);
int process_file(http_t *req, http_t *resp);

int usage(const char *pname)
{
  emsg(">> Usage: %s [options]", pname);
  emsg("Options");
  emsg("  -d, --home        Home Directory of Assets");
  emsg("  -p, --port        Listening Port Number");
  emsg("  -c, --cert        TLS Certificate");
  emsg("  -k, --key         Private Key");
  emsg("  -a, --cacert      CA Certificate");
  exit(1);
}

int main(int argc, char *argv[])
{
  http_cbs_t *cbs;
  http_t *req, *resp;

  SSL_CTX *ctx;
  SSL_METHOD *method;
  SSL *ssl;
  EC_KEY *ecdh;

  int c, server, client, err, port, ret;
  const char *pname;
  const char *home;
  const char *cert;
  const char *pkey;
  const char *cacert;

  struct sockaddr_in addr;
  socklen_t len = sizeof(addr);

  pname = argv[0];
  home = NULL;
  cert = NULL;
  pkey = NULL;
  cacert = NULL;
  port = -1;
  err = 0;
  dtype = DPI_DEBUG_SERVER|DPI_DEBUG_LIBRARY;

  while (1)
  {
    int option_index = 0;
    static struct option long_options[] = {
      {"home", required_argument, 0, 'd'},
      {"port", required_argument, 0, 'p'},
      {"cert", required_argument, 0, 'c'},
      {"key", required_argument, 0, 'k'},
      {"cacert", required_argument, 0, 'a'},
      {0, 0, 0, 0}
    };

    const char *opt = "d:p:c:k:a:0";

    c = getopt_long(argc, argv, opt, long_options, &option_index);

    if (c == -1)
      break;
    
    switch (c)
    {
      case 'd':
        home = optarg;
        if (access(home, F_OK) == -1)
          err |= ERR_INVALID_HOME_DIRECTORY_PATH;
        break;

      case 'p':
        port = atoi(optarg);
        break;

      case 'c':
        cert = optarg;
        if (access(cert, F_OK) == -1)
          err |= ERR_INVALID_CERTIFICATE_PATH;
        break;

      case 'k':
        pkey = optarg;
        if (access(pkey, F_OK) == -1)
          err |= ERR_INVALID_PRIVATE_KEY_PATH;
        break;

      case 'a':
        cacert = optarg;
        if (access(cacert, F_OK) == -1)
          err |= ERR_INVALID_CA_CERTIFICATE_PATH;
        break;

      default:
        usage(pname);
    }
  }

  if (!home)
  {
    emsg("Please specify the home directory of the server assets");
    usage(pname);
  }

  if (!cert)
  {
    emsg("Please specify the path of the TLS certificate file");
    usage(pname);
  }

  if (!pkey)
  {
    emsg("Please specify the path of the private key file");
    usage(pname);
  }

  if (!cacert)
  {
    emsg("Please specify the path of the CA certificate file");
    usage(pname);
  }

  if (port < 0)
  {
    emsg("Please specify the listening port number");
    usage(pname);
  }

  if (err)
  {
    if (err & ERR_INVALID_HOME_DIRECTORY_PATH)
    {
      emsg("Invalid home directory path: %s", home);
    }

    if (err & ERR_INVALID_CERTIFICATE_PATH)
    {
      emsg("Invalid TLS certificate path: %s", cert);
    }

    if (err & ERR_INVALID_PRIVATE_KEY_PATH)
    {
      emsg("Invalid private key path: %s", pkey);
    }

    if (err & ERR_INVALID_CA_CERTIFICATE_PATH)
    {
      emsg("Invalid CA certificate path: %s", pkey);
    }

    usage(pname);
  }

  SSL_load_error_strings();
  init_http_module();

  method = (SSL_METHOD *)TLS_server_method();
  ctx = SSL_CTX_new(method);

  if (SSL_CTX_load_verify_locations(ctx, cacert, NULL) != 1)
  {
    emsg("SSL_CTX_load_verify_locations() error");
    ERR_print_errors_fp(stderr);
    goto err;
  }

  if (SSL_CTX_use_certificate_file(ctx, cert, SSL_FILETYPE_PEM) <= 0)
  {
    emsg("SSL_CTX_use_certificate_file() error");
    ERR_print_errors_fp(stderr);
    goto err;
  }

  if (SSL_CTX_use_PrivateKey_file(ctx, pkey, SSL_FILETYPE_PEM) <= 0)
  {
    emsg("SSL_CTX_use_PrivateKey_file() error");
    ERR_print_errors_fp(stderr);
    goto err;
  }

  if (!SSL_CTX_check_private_key(ctx))
  {
    emsg("SSL_CTX_check_private_key() error");
    ERR_print_errors_fp(stderr);
    goto err;
  }

  ecdh = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
  if (!ecdh)
  {
    emsg("Set ECDH error");
    ERR_print_errors_fp(stderr);
    goto err;
  }

  if (SSL_CTX_set_tmp_ecdh(ctx, ecdh) != 1)
  {
    emsg("SSL_CTX_set_tmp_ecdh() error");
    ERR_print_errors_fp(stderr);
    goto err;
  }

  cbs = init_http_callbacks();
  if (!cbs) goto err;

  ret = register_callback(cbs, HTTP_METHOD_GET, "/", 1, process_index);
  if (ret != HTTP_SUCCESS) goto err;

  ret = register_callback(cbs, HTTP_METHOD_GET, "/json", 5, process_json);
  if (ret != HTTP_SUCCESS) goto err;

  ret = register_callback(cbs, HTTP_METHOD_GET, "/file", 5, process_file);

  print_callbacks(cbs);

  server = open_listener(port, 1);
  if (server < 0)
    abort();

  while(1)
  {
    if((client = accept(server, (struct sockaddr *)&addr, &len)) > 0)
    {
      dmsg(DPI_DEBUG_SERVER, "New connection is accepted");
      break;
    }
  }

  ssl = SSL_new(ctx);
  SSL_set_fd(ssl, client);
  SSL_set_accept_state(ssl);

  req = init_http_message(HTTP_TYPE_REQUEST);
  if (!req) goto err;

  resp = init_http_message(HTTP_TYPE_RESPONSE);
  if (!resp) goto err;
  http_set_default_attributes(resp);

  while (!err)
  {
    ret = SSL_do_handshake(ssl);
    err = process_error(ssl, ret);

    if (err < 0)
      abort();
  }
  dmsg(DPI_DEBUG_SERVER, "TLS session is established with %s", SSL_get_cipher(ssl));

  ret = HTTP_NOT_FINISHED;
  while (ret == HTTP_NOT_FINISHED)
    ret = recv_https_message(ssl, req, NULL);
  if (ret != HTTP_SUCCESS) goto err;
  print_header(req);

  process_request(cbs, req, resp);

  print_header(resp);
  ret = HTTP_NOT_FINISHED;
  while (ret == HTTP_NOT_FINISHED)
    ret = send_https_message(ssl, resp);
  if (ret != HTTP_SUCCESS) goto err;

  SSL_shutdown(ssl);
  close(client);
  close(server);

err:
  if (ssl)
    SSL_free(ssl);

  if (ctx)
    SSL_CTX_free(ctx);

  return 0;
}

int process_index(http_t *req, http_t *resp)
{
  fstart("req: %p, resp: %p", req, resp);
  assert(req != NULL);
  assert(resp != NULL);

  dmsg(DPI_DEBUG_SERVER, "process_index()!");

  resource_t *resource;
  uint8_t *buf;

  resource = http_init_resource(resp);
  buf = (uint8_t *)malloc(7);
  memcpy(buf, "Hello!\n", 7);

  resource->type = HTTP_RESOURCE_MEM;
  resource->ptr = (void *)buf;
  resource->size = 7;

  ffinish();
  return HTTP_SUCCESS;
}

int process_json(http_t *req, http_t *resp)
{
  fstart("req: %p, resp: %p", req, resp);
  assert(req != NULL);
  assert(resp != NULL);

  dmsg(DPI_DEBUG_SERVER, "process_json()!");

  ffinish();
  return HTTP_SUCCESS;
}

int process_file(http_t *req, http_t *resp)
{
  fstart("req: %p, resp: %p", req, resp);
  assert(req != NULL);
  assert(resp != NULL);

  ffinish();
  return HTTP_SUCCESS;
}
