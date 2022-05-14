#include <stdio.h>
#include <errno.h>
#include <unistd.h>
#include <malloc.h>
#include <string.h>
#include <time.h>
#include <resolv.h>
#include <netdb.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <sys/time.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <getopt.h>

#include <dpi/debug.h>
#include <dpi/defines.h>

//#include "log_client.h"

#define FAIL          -1
#define BUF_SIZE      16384
#define DHFILE        "dh1024.pem"
#define MAX_HOST_LEN  256

#define DELIMITER     "\r\n"
#define DELIMITER_LEN 2

#define INDEX_FILE      "/index.html"
#define INDEX_FILE_LEN  12

struct rinfo
{
  uint8_t *domain;
  uint32_t dlen;
  uint8_t *content;
  size_t total;
  uint32_t clen;
  uint32_t size;
  uint32_t sent;
  int hsent;
};

int dtype;
int open_listener(int port);
SSL_CTX* init_server_ctx(void);
void load_certificates(SSL_CTX* ctx);
void load_dh_params(SSL_CTX *ctx, char *file);
void load_ecdh_params(SSL_CTX *ctx);
int running = 1;
int http_parse_request(uint8_t *msg, uint32_t mlen, struct rinfo *r);
size_t fetch_content(uint8_t *buf, struct rinfo *r);
int fetch_cert(SSL *ssl, int *ad, void *arg);
unsigned long get_current_time(void);
unsigned long get_current_cpu(void);

void int_handler(int dummy)
{
  emsg("End of experiment");
  running = 0;
  exit(0);
}

int usage(const char *pname)
{
  emsg(">> Usage: %s [options]", pname);
  emsg("Options");
  emsg("  -p, --port        Listening Port Number");
  emsg("  -l, --length      Length");
  emsg("  -m, --mtdpi       Enable MT-DPI");
  emsg("  -b, --blindbox    Enable Blindbox");
  exit(1);
}

int main(int argc, char *argv[])
{  
	SSL *ssl;
	SSL_CTX *ctx;
	int c, server, client, sent = -1, rcvd = -1, port, offset, tbs, tbr, mtdpi, blindbox;
  const char *pname;
  uint8_t rbuf[BUF_SIZE] = {0, };
  uint8_t wbuf[BUF_SIZE] = {0, };
  uint8_t *p;
  struct rinfo r = {0, };
  unsigned long tstart, tmid, tend, cstart, cend;
  int length;

  dtype = DPI_DEBUG_SERVER|DPI_DEBUG_LIBRARY;
  pname = argv[0];
  port = -1;
  length = 0;
  mtdpi = 0;
  blindbox = 0;

  signal(SIGINT, int_handler);

  while (1)
  {
    int option_index = 0;
    static struct option long_options[] = {
      {"port", required_argument, 0, 'p'},
      {"length", required_argument, 0, 'l'},
      {"mtdpi", required_argument, 0, 'm'},
      {"blindbox", required_argument, 0, 'b'},
      {0, 0, 0, 0}
    };

    const char *opt = "p:l:mb0";

    c = getopt_long(argc, argv, opt, long_options, &option_index);

    if (c == -1)
      break;
    
    switch (c)
    {
      case 'p':
        port = atoi(optarg);
        break;

      case 'l':
        length = atoi(optarg);
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

  if (port < 0)
  {
    emsg("Please specify the listening port number");
    usage(pname);
  }

  if (!length)
  {
    emsg("Length should be set");
    usage(pname);
  }

  if (mtdpi == 1 && blindbox == 1)
  {
    emsg("MT-DPI and Blindbox should not be enabled simultaneously");
    usage(pname);
  }

	SSL_library_init();
	OpenSSL_add_all_algorithms();

	ctx = init_server_ctx();
  load_ecdh_params(ctx);
	load_certificates(ctx);
	imsg(DPI_DEBUG_SERVER, "load_certificates success");

	server = open_listener(port);    /* create server socket */

	struct sockaddr_in addr;
	socklen_t len = sizeof(addr);

	while (running)
	{
    if ((client = accept(server, (struct sockaddr *)&addr, &len)) > 0)
    {
      imsg(DPI_DEBUG_SERVER, "New Connection is accepted: mtdpi: %d, blindbox: %d", mtdpi, blindbox);
      tstart = get_current_time();
		  ssl = SSL_new(ctx);
		  SSL_set_fd(ssl, client);

      if (mtdpi)
      {
        SSL_enable_mt_dpi(ssl);
        printf("MT-DPI is enabled\n");
      }

      if (blindbox)
      {
        SSL_enable_blindbox(ssl);
        printf("Blindbox is enabled\n");
      }

		  if ( SSL_accept(ssl) == FAIL )
			  ERR_print_errors_fp(stderr);

      while (rcvd <= 0)
        rcvd = SSL_read(ssl, rbuf, BUF_SIZE);

      p = wbuf;
      VAR_TO_PTR_4BYTES(length, p);
      tbs = 4;
      offset = 0;
      while (offset < tbs)
      {
        sent = SSL_write(ssl, wbuf, 4);
        if (sent > 0)
          offset += sent;
      }
      assert(offset == tbs);

      tbs = length;
      offset = 0;
      tmid = get_current_time();
      while (offset < tbs)
      {
        if ((tbs - offset) < BUF_SIZE)
          len = (tbs - offset);
        else
          len = BUF_SIZE;
        sent = SSL_write(ssl, wbuf, len);
        if (sent > 0)
          offset += sent;
      }
      assert(offset == tbs);
      tend = get_current_time();
      imsg(DPI_DEBUG_SERVER, "Send Time: %lu ns", tend - tmid);
      imsg(DPI_DEBUG_SERVER, "Elapsed Time: %lu ns", tend - tstart);
      imsg(DPI_DEBUG_SERVER, "CPU Time: %lu ns", cend - cstart);

      imsg(DPI_DEBUG_SERVER, "HTTP Request Length: %d, HTTP Response Length: %d (len: %d bytes)", rcvd, offset, offset);

		  if (sent != len)
		  {
			  emsg("SERVER: Send the HTTP Test Page Failed: %d", sent);
			  abort();
		  } 
		  imsg(DPI_DEBUG_SERVER, "SERVER: Send the HTTP Test Page Success: %d", offset);
      
      //close(client);
      //SSL_free(ssl);

      memset(rbuf, 0x0, BUF_SIZE);
      memset(wbuf, 0x0, BUF_SIZE);
    }
	}

	SSL_CTX_free(ctx);
	close(server);

	return 0;
}

int open_listener(int port)
{   
  int sd;
	struct sockaddr_in addr;

	sd = socket(PF_INET, SOCK_STREAM, 0);
	
	bzero(&addr, sizeof(addr));
	addr.sin_family = AF_INET;
	addr.sin_port = htons(port);
	addr.sin_addr.s_addr = INADDR_ANY;
	if ( bind(sd, (struct sockaddr*)&addr, sizeof(addr)) != 0 )
	{
		perror("can't bind port");
		abort();
	}
	if ( listen(sd, 10) != 0 )
	{
		perror("Can't configure listening port");
		abort();
	}
	return sd;
}

SSL_CTX* init_server_ctx(void)
{   
	SSL_METHOD *method;
	SSL_CTX *ctx;

	SSL_load_error_strings();
	method = (SSL_METHOD *) TLS_server_method();
	ctx = SSL_CTX_new(method);
	if (!ctx)
	{
		emsg("SSL_CTX init failed!");
		abort();
	}

	return ctx;
}

void load_certificates(SSL_CTX* ctx)
{
	/* Load certificates for verification purpose*/
	if (SSL_CTX_load_verify_locations(ctx, NULL, "/etc/ssl/certs") != 1)
	{
		ERR_print_errors_fp(stderr);
		abort();
	}

	/* Set default paths for certificate verifications */
	if (SSL_CTX_set_default_verify_paths(ctx) != 1)
	{
		ERR_print_errors_fp(stderr);
		abort();
	}

  SSL_CTX_set_tlsext_servername_callback(ctx, fetch_cert);
}

void load_dh_params(SSL_CTX *ctx, char *file)
{
  DH *ret = 0;
  BIO *bio;

  if ((bio = BIO_new_file(file, "r")) == NULL)
  {
    perror("Couldn't open DH file");
  }

  BIO_free(bio);

  if (SSL_CTX_set_tmp_dh(ctx, ret) < 0)
  {
    perror("Couldn't set DH parameters");
  }
}

void load_ecdh_params(SSL_CTX *ctx)
{
  EC_KEY *ecdh = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);

  if (!ecdh)
    perror("Couldn't load the ec key");

  if (SSL_CTX_set_tmp_ecdh(ctx, ecdh) != 1)
    perror("Couldn't set the ECDH parameter (NID_X9_62_prime256v1)");
}

int fetch_cert(SSL *ssl, int *ad, void *arg)
{
  fstart("ssl: %p, ad: %p, arg: %p", ssl, ad, arg);
  (void) ad;
  (void) arg;

  int ret;
  uint8_t crt_path[MAX_HOST_LEN];
  uint8_t priv_path[MAX_HOST_LEN];
  uint8_t *p;
  uint32_t len;

  if (!ssl)
    return SSL_TLSEXT_ERR_NOACK;

  const char *name = SSL_get_servername(ssl, TLSEXT_NAMETYPE_host_name);
  if (!name || name[0] == '\0')
    return SSL_TLSEXT_ERR_NOACK;

  memset(crt_path, 0x0, MAX_HOST_LEN);
  memset(priv_path, 0x0, MAX_HOST_LEN);

  p = crt_path;
  len = strlen(name);
  memcpy(p, name, len);

  ret = mkdir((const char *)p, 0775);
  if (ret < 0)
  {
    if (errno == EEXIST)
    {
      dmsg(DPI_DEBUG_SERVER, "The directory exists");
    }
    else
    {
      dmsg(DPI_DEBUG_SERVER, "Other error");
    }
  }

  p += len;
  memcpy(p, "/cert.der", 9);

  p = priv_path;
  len = strlen(name);
  memcpy(p, name, len);

  p += len;
  memcpy(p, "/priv.der", 9);

  dmsg(DPI_DEBUG_SERVER, "crt_path: %s", crt_path);
  dmsg(DPI_DEBUG_SERVER, "priv_path: %s", priv_path);

  if (SSL_use_certificate_file(ssl, (const char *)crt_path, SSL_FILETYPE_ASN1) != 1)
  {
    emsg("Loading the certificate error");
    return SSL_TLSEXT_ERR_NOACK;
  }

  imsg(DPI_DEBUG_SERVER, "Loading the certificate success");

  if (SSL_use_PrivateKey_file(ssl, (const char *)priv_path, SSL_FILETYPE_ASN1) != 1)
  {
    emsg("Loading the private key error");
    return SSL_TLSEXT_ERR_NOACK;
  }
  
  imsg(DPI_DEBUG_SERVER, "Loading the private key success");

  if (SSL_check_private_key(ssl) != 1)
  {
    emsg("Checking the private key error");
    return SSL_TLSEXT_ERR_NOACK;
  }

  imsg(DPI_DEBUG_SERVER, "Checking the private key success");

  ffinish();
  return SSL_TLSEXT_ERR_OK;
}

size_t fetch_content(uint8_t *buf, struct rinfo *r)
{
  fstart("buf: %p, r: %p", buf, r);

	const char *resp = 	
		"HTTP/1.1 200 OK\r\n"
		"Content-Type: text/html\r\n"
		"Content-Length: %ld\r\n"
		"\r\n";

  FILE *fp;
  size_t total, sz;
  uint8_t path[MAX_HOST_LEN];
  uint8_t *p;
  int rlen;
  rlen = 0;

  memset(path, 0x0, MAX_HOST_LEN);
  p = path;

  memcpy(p, r->domain, r->dlen);
  p += r->dlen;
  
  memcpy(p, r->content, r->clen);

  imsg(DPI_DEBUG_SERVER, "path: %s", path);

  fp = fopen((const char *)path, "rb");

  if (!fp)
  {
    emsg("Error in opening the file");
    return -1;
  }

  fseek(fp, 0L, SEEK_END);
  total = ftell(fp);
  r->total = total;
  sz = total - r->sent;
  imsg(DPI_DEBUG_SERVER, "sz: %ld, r->sent: %u", sz, r->sent);

  if (sz > BUF_SIZE)
    sz = BUF_SIZE;

  fseek(fp, r->sent, SEEK_SET);

  memset(buf, 0x0, BUF_SIZE);
  p = buf;
  if (!r->hsent)
  {
    snprintf((char *)p, BUF_SIZE, resp, total);
    r->hsent = 1;
  }
  rlen = strlen((const char *)buf);
  p += rlen;
  fread(p, 1, sz, fp);
  fclose(fp);

  ffinish("sz: %ld, rlen: %d", sz, rlen);
  return sz + rlen;
}

int http_parse_request(uint8_t *msg, uint32_t mlen, struct rinfo *r)
{
  fstart("msg: %s, mlen: %d, r: %p", msg, mlen, r);
  (void) mlen;
  int l;
  uint8_t *cptr, *nptr, *p, *q;
  struct rinfo *info;

#ifdef DEBUG
  uint8_t buf[MAX_HOST_LEN] = {0};
#endif /* DEBUG */
  
  info = r;
  cptr = msg;

  while ((nptr = strstr((const char *)cptr, DELIMITER)))
  {
    l = nptr - cptr;

#ifdef DEBUG
    memcpy(buf, cptr, l);
    buf[l+1] = 0;
    printf("Token (%d bytes): %s\n", l, buf);
#endif /* DEBUG */

    p = cptr;
    
    while (*p == ' ')
      p++;

    if ((l > 0) && (strncmp((const char *)p, "GET", 3) == 0))
    {
      p += 3;

      while (*p != '/')
        p++;

      q = p;

      while (*q != ' ')
        q++;

      if (q - p == 1)
      {
        info->content = (uint8_t *)malloc(INDEX_FILE_LEN);
        memset(info->content, 0x0, INDEX_FILE_LEN);
        memcpy(info->content, INDEX_FILE, INDEX_FILE_LEN);
        info->clen = INDEX_FILE_LEN;
      }
      else
      {
        info->content = (uint8_t *)malloc(q - p);
        memcpy(info->content, p, q - p);
        info->clen = q - p;
      }
    }

    if ((l > 0) && (strncmp((const char *)p, "Host:", 5) == 0))
    {
      p += 5;

      while (*p == ' ')
        p++;

      info->domain = (uint8_t *)malloc(nptr - p);
      memcpy(info->domain, p, nptr - p);
      info->dlen = nptr - p;
    }

    cptr = nptr + DELIMITER_LEN;

#ifdef DEBUG
    memset(buf, 0x0, MAX_HOST_LEN);
#endif /* DEBUG */
  }

  dmsg(DPI_DEBUG_SERVER, "Domain name in parser (%d bytes): %s", info->dlen, info->domain);
  dmsg(DPI_DEBUG_SERVER, "Content name in parser (%d bytes): %s", info->clen, info->content);
  ffinish();
  return 1;
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

