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
#include <netinet/tcp.h>
#include <pthread.h>
#include <fcntl.h>
#include <getopt.h>

#include <dpi/debug.h>

#define FAIL    -1
#define BUF_SIZE 1024
#define MAX_THREADS 100
#define MAX_CLNT_SIZE 10

int open_listener(int port);
int open_connection(const char *hostname, int port);
SSL_CTX *init_middlebox_ctx(void);
SSL_CTX *init_client_ctx(void);
void load_certificates(SSL_CTX* ctx, const char *cert, const char *pkey, 
    const char *cacert);
void load_ecdh_params(SSL_CTX *ctx);
void *mb_run(void *data);
void init_thread_config(void);
int get_thread_index(void);
unsigned long cstart, cend;
unsigned long get_current_cpu(void);

pthread_t threads[MAX_THREADS];
pthread_attr_t attr;
int tidx;

struct info
{
  int sock;
  SSL_CTX *mctx;
  SSL_CTX *cctx;
};

int usage(const char *pname)
{
  emsg(">> Usage: %s [options]", pname);
  emsg("Options");
  emsg("  -1, --port        Middlebox Listening Port Number");
  emsg("  -2, --cert        Middlebox Certificate");
  emsg("  -3, --key         Private Key");
  emsg("  -4, --cacert      CA Certificate");
  emsg("  -n, --name        DPI Name");
  emsg("  -r, --rule        Rule Filename");

  exit(1);
}

int main(int argc, char *argv[])
{  
	int c, server, client, rc, port;
	char *name, *pname, *rname, *cert, *pkey, *cacert;
  void *status;
  SSL_CTX *mctx, *cctx;

  tidx = 0;
  pname = argv[0];
  cert = NULL;
  pkey = NULL;
  cacert = NULL;
  mctx = NULL;
  cctx = NULL;
  port = -1;

  while (1)
  {
    int option_index = 0;
    static struct option long_options[] = {
      {"port", required_argument, 0, '1'},
      {"cert", required_argument, 0, '2'},
      {"key", required_argument, 0, '3'},
      {"cacert", required_argument, 0, '4'},
      {"name", required_argument, 0, 'n'},
      {"rule-filename", required_argument, 0, 'r'},
      {0, 0, 0, 0}
    };

    const char *opt = "1:2:3:4:n:r:0";

    c = getopt_long(argc, argv, opt, long_options, &option_index);

    if (c == -1)
      break;
    
    switch (c)
    {
      case '1':
        port = atoi(optarg);
        break;

      case '2':
        cert = optarg;
        if (access(cert, F_OK) == -1)
        {
          emsg("invalid a certificate path: %s", cert);
          usage(pname);
        }
        break;

      case '3':
        pkey = optarg;
        if (access(pkey, F_OK) == -1)
        {
          emsg("invalid a private key path: %s", pkey);
          usage(pname);
        }
        break;

      case '4':
        cacert = optarg;
        if (access(cacert, F_OK) == -1)
        {
          emsg("invalid a ca certificate path: %s", cacert);
          usage(pname);
        }
        break;

      case 'n':
        name = optarg;
        break;

      case 'r':
        rname = optarg;
        break;

      default:
        usage(pname);
    }
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
    emsg("Please specify the port number of the forwarder to be connected");
    usage(pname);
  }

	SSL_library_init();
	OpenSSL_add_all_algorithms();

	mctx = init_middlebox_ctx();
	load_certificates(mctx, cert, pkey, cacert);
  load_ecdh_params(mctx);

  cctx = init_client_ctx();
  load_ecdh_params(cctx);

  init_thread_config();
	server = open_listener(port);

	struct sockaddr_in addr;
	socklen_t len = sizeof(addr);

	while (1)
	{
    client = accept(server, (struct sockaddr *)&addr, &len);

    if (client < 0)
    {
      emsg("error in accept");
      exit(EXIT_FAILURE);
    }

    struct info *info = (struct info *)malloc(sizeof(struct info));
    info->sock = client;
    info->mctx = mctx;
    info->cctx = cctx;
    tidx = get_thread_index();
    imsg(DPI_DEBUG_MIDDLEBOX, "Create thread with index: %d", tidx);
    rc = pthread_create(&threads[tidx], &attr, mb_run, info);

    if (rc < 0)
    {
      emsg("error in pthread create");
      exit(EXIT_FAILURE);
    }

    pthread_attr_destroy(&attr);

    rc = pthread_join(threads[tidx], &status);

    if (rc)
    {
      emsg("error in join");
      exit(EXIT_FAILURE);
    }
    close(client);
	}

	SSL_CTX_free(mctx);
	SSL_CTX_free(cctx);
	close(server);

	return 0;
}

void *mb_run(void *data)
{
  imsg(DPI_DEBUG_MIDDLEBOX, "start server loop");
  struct info *info;
  int i, server, client, rcvd, sent, flags, exit;
  unsigned char buf[BUF_SIZE];

  SSL *ssl[2];
  SSL_CTX *mctx, *cctx;
  info = (struct info *)data;
  client = info->sock;
  mctx = info->mctx;
  cctx = info->cctx;
  ssl[0] = SSL_new(mctx);
  SSL_set_fd(ssl[0], client);

  SSL_set_accept_state(ssl[0]);
  SSL_accept(ssl[0]);

  server = open_connection("www.mt-dpi.com", 5556);
  ssl[1] = SSL_new(cctx);
  SSL_set_fd(ssl[1], server);
  SSL_set_connect_state(ssl[1]);
  SSL_set_tlsext_host_name(ssl[1], "www.mt-dpi.com");
  SSL_connect(ssl[1]);

  flags = fcntl(client, F_GETFL);
  fcntl(client, F_SETFL, flags | O_NONBLOCK);

  flags = fcntl(server, F_GETFL);
  fcntl(server, F_SETFL, flags | O_NONBLOCK);

  exit = 0;
  while (!exit)
  {
    for (i=0; i<2; i++)
    {
      rcvd = SSL_read(ssl[i], buf, BUF_SIZE);
      if (rcvd == 0)
      {
        printf("disconnected\n");
        exit = 1;
        break;
      }

      // TODO: keyword matching

      sent = SSL_write(ssl[1-i], buf, rcvd);
    }
  }

  for (i=0; i<2; i++)
    SSL_free(ssl[i]);

  return NULL;
}

int open_listener(int port)
{   int sd;
	struct sockaddr_in addr;

	sd = socket(PF_INET, SOCK_STREAM, 0);
//  if (setsockopt(sd, SOL_TCP, TCP_NODELAY, &(int){1}, sizeof(int)) < 0)
//    perror("setsockopt(SO_REUSEADDR) failed");

	bzero(&addr, sizeof(addr));
	addr.sin_family = AF_INET;
	addr.sin_port = htons(port);
	addr.sin_addr.s_addr = INADDR_ANY;
	if ( bind(sd, (struct sockaddr*)&addr, sizeof(addr)) != 0 )
	{
		perror("can't bind port");
		abort();
	}
	if ( listen(sd, MAX_CLNT_SIZE) != 0 )
	{
		perror("Can't configure listening port");
		abort();
	}
	return sd;
}

int open_connection(const char *hostname, int port)
{   
  int sd;
  struct hostent *host;
  struct sockaddr_in addr;
            
  if ( (host = gethostbyname(hostname)) == NULL )
  {
    perror(hostname);
    abort();
  }
    
  sd = socket(PF_INET, SOCK_STREAM, 0);
  bzero(&addr, sizeof(addr));
  addr.sin_family = AF_INET;
  addr.sin_port = htons(port);
  addr.sin_addr.s_addr = *(long*)(host->h_addr);

  if ( connect(sd, (struct sockaddr*)&addr, sizeof(addr)) != 0 )
  {
    close(sd);
    perror(hostname);
    abort();
  }
         
  return sd;
}

SSL_CTX* init_middlebox_ctx(void)
{   
	SSL_METHOD *method;
  SSL_CTX *ctx;

	SSL_load_error_strings();   /* load all error messages */
	method = (SSL_METHOD *) TLS_method();  /* create new server-method instance */
	ctx = SSL_CTX_new(method);   /* create new context from method */
	if (!ctx)
	{
		emsg("SSL_CTX init failed");
		abort();
	}

  SSL_CTX_set_max_proto_version(ctx, TLS1_3_VERSION);
  SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION);
  SSL_CTX_set_ciphersuites(ctx, "TLS_AES_128_GCM_SHA256:TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256");

	return ctx;
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

void load_certificates(SSL_CTX *ctx, const char *cert, const char *key, const char *cacert)
{
	if (SSL_CTX_load_verify_locations(ctx, cacert, NULL) != 1)
	{
		ERR_print_errors_fp(stderr);
		abort();
	}
	else
  {
		dmsg(DPI_DEBUG_MIDDLEBOX, "SSL_CTX_load_verify_locations success");
  }

	if ( SSL_CTX_use_certificate_file(ctx, cert, SSL_FILETYPE_PEM) <= 0 )
	{
		ERR_print_errors_fp(stderr);
		abort();
	}
	else
  {
	  dmsg(DPI_DEBUG_MIDDLEBOX, "SSL_CTX_use_certificate_file success");
  }

	if ( SSL_CTX_use_PrivateKey_file(ctx, key, SSL_FILETYPE_PEM) <= 0 )
	{
		ERR_print_errors_fp(stderr);
		abort();
	}
	else
  {
		dmsg(DPI_DEBUG_MIDDLEBOX, "SSL_CTX_use_PrivateKey_file success");
  }

	if ( !SSL_CTX_check_private_key(ctx) )
	{
		ERR_print_errors_fp(stderr);
		abort();
	}
	else
  {
		dmsg(DPI_DEBUG_MIDDLEBOX, "SSL_CTX_check_private_key success");
  }
}

void init_thread_config(void)
{
  pthread_attr_init(&attr);
  pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_JOINABLE);
}

int get_thread_index(void)
{
  int i, ret = -1;

  for (i=0; i<MAX_THREADS; i++)
  {
    if (!threads[i])
    {
      ret = i;
      break;
    }
  }

  return ret;
}

void load_ecdh_params(SSL_CTX *ctx) {
	EC_KEY *ecdh;
	ecdh = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);

	if (!ecdh)
		perror("Couldn't load the ec key");

	if (SSL_CTX_set_tmp_ecdh(ctx, ecdh) != 1)
		perror("Couldn't set the ECDH parameter (NID_X9_62_prime256v1)");
}

unsigned long get_current_cpu(void)
{
  struct timespec tp;
  clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &tp);
  return tp.tv_sec * 1000000000 + tp.tv_nsec;
}

