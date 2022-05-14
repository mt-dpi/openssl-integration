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
#include <getopt.h>
#include <pthread.h>

#include <dpi/dpi.h>
#include <dpi/debug.h>
#include <dpi/circuit_randomization.h>

#define FAIL    -1
#define MAX_THREADS 10
#define KEYWORD_LENGTH 8

int dtype = DPI_DEBUG_INIT;
int open_listener(int port);
SSL_CTX* init_server_ctx(void);
void load_certificates(SSL_CTX* ctx, char* cert, char* key);
void load_dh_params(SSL_CTX *ctx, char *file);
void load_ecdh_params(SSL_CTX *ctx);
void *run(void *data);

typedef struct arg_st {
  int client;
  char *rname;
} arg_t;

unsigned long get_current_clock_time(void)
{
  struct timespec ts;
  clock_gettime(CLOCK_MONOTONIC, &ts);
  return ts.tv_sec * 1000000000 + ts.tv_nsec;
}

void usage(const char *pname)
{
  emsg(">> Usage: %s [options]", pname);
  emsg(">> Options");
  emsg("  -p, --port            port number");
  emsg("  -r, --rname           rule filename");
  exit(1);
}

int main(int argc, char *argv[])
{  
	SSL_CTX *ctx;
	int i, idx, c, rc, server, client, port, num_of_threads;
  pthread_t thread[MAX_THREADS];
  pthread_attr_t attr;
  arg_t args[MAX_THREADS];
  void *status;
  char *opt, *pname, *rname;

  pname = argv[0];
  rname = NULL;
  port = -1;

  while (1)
  {
    int opt_idx = 0;
    static struct option long_options[] = {
      {"port", required_argument, 0, 'p'},
      {"rname", required_argument, 0, 'r'},
      {0, 0, 0, 0}
    };

    opt = "p:r:0";

    c = getopt_long(argc, argv, opt, long_options, &opt_idx);

    if (c == -1)
      break;

    switch (c)
    {
      case 'p':
        port = atoi(optarg);
        break;
      case 'r':
        rname = optarg;
        break;
      default:
        usage(pname);
    }
  }
  
  if (port < 0)
  {
    emsg("Port number is not set");
    usage(pname);
  }

  if (!rname)
  {
    emsg("Rule filename is not set");
    usage(pname);
  }

  assert(port > 0 && port < 65536);
  imsg(DPI_DEBUG_INIT, "Port: %d", port);

  pthread_attr_init(&attr);
  pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_JOINABLE);

	server = open_listener(port);    /* create server socket */

	struct sockaddr_in addr;
	socklen_t len = sizeof(addr);

  idx = 0;
	while (1)
	{
    if ((client = accept(server, (struct sockaddr *)&addr, &len)) > 0)
    {
      imsg(DPI_DEBUG_INIT, "accept the client: %d", client);
      if (idx < MAX_THREADS)
      {
        args[idx].client = client;
        args[idx].rname = rname;
        rc = pthread_create(&thread[idx], &attr, run, &args[idx]);
        if (rc)
        {
          emsg("return code from pthread_create: %d", rc);
          return 1;
        }
        idx++;
      }
    }
	}

  pthread_attr_destroy(&attr);

  for (i=0; i<num_of_threads; i++)
  {
    rc = pthread_join(thread[i], &status);

    if (rc)
    {
      emsg("return code from pthread_join: %d", rc);
      return 1;
    }
  }
  
	SSL_CTX_free(ctx);
	close(server);

	return 0;
}

void *run(void *data)
{
  int i, idx, sock, klen, nrules, bsize, clen, tbs, tbr, sent, rcvd, offset, cid;
  uint8_t a, b, c, ch;
  arg_t *arg;
  const char *rname;
  char *keyword;
  uint8_t buf[BUF_SIZE] = {0, };
  uint8_t pkey[16] = {0, };
  uint8_t random[16] = {3, };
  uint8_t **cert;
  uint8_t *p;
  FILE *fp;
  size_t len;
  ssize_t rlen;
  mb_input_t *input;
  unsigned long start, end;

  fp = NULL;
  nrules = 0;
  bsize = 16;
  klen = KEYWORD_LENGTH;
  arg = (arg_t *)data;
  sock = arg->client;
  rname = arg->rname;
  input = (mb_input_t *)calloc(1, sizeof(mb_input_t));

  // Test Reason
  input->pkey = (uint8_t *)calloc(bsize, sizeof(uint8_t));
  input->plen = bsize;
  input->random = (uint8_t *)calloc(bsize, sizeof(uint8_t));
  memcpy(input->random, random, bsize);
  input->rlen = bsize;

  fernet_random_ot(DPI_ROLE_MIDDLEBOX, sock, &a, &b, &c);

  fp = fopen(rname, "r");
  if (!fp) goto out;

  nrules = 0;
  while (!feof(fp))
  {
    ch = fgetc(fp);
    if (ch == '\n')
      nrules++;
  }
  imsg(DPI_DEBUG_CIRCUIT, "# of Keywords: %d", nrules);
  cert = (uint8_t **)calloc(nrules, sizeof(uint8_t*));
  for (i=0; i<nrules; i++)
    cert[i] = (uint8_t *)calloc(bsize, sizeof(uint8_t));
  fclose(fp);

  fp = fopen(rname, "r");
  if (!fp) goto out;

  p = buf;
  VAR_TO_PTR_4BYTES(nrules, p);
  tbs = (p-buf);
  offset = 0;
  while (offset < tbs)
  {
    sent = write(sock, buf+offset, tbs-offset);
    offset += sent;
  }
  assert(offset == tbs);

  idx = 0;
  while ((rlen = getline(&keyword, &len, fp)) != -1)
  {
    generate_certificate(keyword, klen, pkey, random, bsize, cert[idx], &clen);
    assert(clen == bsize);
    tbs = bsize;
    offset = 0;
    while (offset < tbs)
    {
      sent = write(sock, cert[idx]+offset, tbs-offset);
      offset += sent;
    }
    imsg(DPI_DEBUG_CIRCUIT, "Keyword: %s", keyword);
    iprint(DPI_DEBUG_CIRCUIT, "Certificate", cert[idx], 0, bsize, 16);
    assert(offset == tbs);
    idx++;
  }
  fclose(fp);

  tbr = 4;
  offset = 0;
  while (offset < tbr)
  {
    rcvd = read(sock, buf+offset, tbr-offset);
    offset += rcvd;
  }
  assert(offset == tbr);
  p = buf;
  PTR_TO_VAR_4BYTES(p, cid);

  fp = fopen(rname, "r");
  if (!fp) goto out;

  start = get_current_clock_time();
  for (i=0; i<nrules; i++)
  {
    rlen = getline(&keyword, &len, fp);
    input->cert = cert[i];
    input->clen = bsize;
    input->keyword = keyword;
    input->klen = klen;
    input->cid = cid;
    circuit_randomization(DPI_ROLE_MIDDLEBOX, sock, a, b, c, input);
    free(input->cert = cert[i]);
  }
  fclose(fp);
  end = get_current_clock_time();
  dmsg(DPI_DEBUG_INIT, "start: %lu, end: %lu", start, end);
  printf("Elapsed time for %d rules: %.2f ms\n", nrules, (end - start) * 1.0 / nrules / 1000000);

out:
  dmsg(DPI_DEBUG_INIT, "End of the MB's thread: %d", sock);
  close(sock);
  return NULL;
}

int open_listener(int port)
{   
  int sd, option;
	struct sockaddr_in addr;
  option = 1;

	sd = socket(PF_INET, SOCK_STREAM, 0);
	setsockopt(sd, SOL_SOCKET, SO_REUSEADDR, &option, sizeof(option));

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
	if ( ctx == NULL )
	{
		printf("SSL_CTX init failed!");
		abort();
	}

  SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);

	return ctx;
}

void load_certificates(SSL_CTX* ctx, char* cert, char* key)
{
	if (SSL_CTX_load_verify_locations(ctx, "ca_ecc_alice.pem", "/etc/ssl/certs") != 1)
	{
		ERR_print_errors_fp(stderr);
		abort();
	}
	else
  {
		emsg("SSL_CTX_load_verify_locations success");
  }

	if (SSL_CTX_set_default_verify_paths(ctx) != 1)
	{
		ERR_print_errors_fp(stderr);
		abort();
	}
	else
  {
		emsg("SSL_CTX_set_default_verify_paths success");
  }

	if ( SSL_CTX_use_certificate_file(ctx, cert, SSL_FILETYPE_PEM) <= 0 )
	{
		ERR_print_errors_fp(stderr);
		abort();
	}
	else
  {
		emsg("SSL_CTX_use_certificate_file success");
  }

	if ( SSL_CTX_use_PrivateKey_file(ctx, key, SSL_FILETYPE_PEM) <= 0 )
	{
		ERR_print_errors_fp(stderr);
		abort();
	}
	else
  {
		emsg("SSL_CTX_use_PrivateKey_file success");
  }

	if ( !SSL_CTX_check_private_key(ctx) )
	{
		ERR_print_errors_fp(stderr);
		abort();
	}
	else
  {
		emsg("SSL_CTX_check_private_key success");
  }
}

void load_dh_params(SSL_CTX *ctx, char *file)
{
  DH *ret = 0;
  BIO *bio;

  if ((bio = BIO_new_file(file, "r")) == NULL)
    perror("Couldn't open the DH file");

  ret = PEM_read_bio_DHparams(bio, NULL, NULL, NULL);
  BIO_free(bio);

  if (SSL_CTX_set_tmp_dh(ctx, ret) != 1)
    perror("Couldn't set the DH parameter");
}

void load_ecdh_params(SSL_CTX *ctx)
{
  EC_KEY *ecdh = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);

  if (!ecdh)
    perror("Couldn't load the ec key");

  if (SSL_CTX_set_tmp_ecdh(ctx, ecdh) != 1)
    perror("Couldn't set the ECDH parameter (NID_X9_62_prime256v1)");
}
