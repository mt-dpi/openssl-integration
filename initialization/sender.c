#include <stdio.h>
#include <errno.h>
#include <unistd.h>
#include <malloc.h>
#include <string.h>
#include <time.h>
#include <resolv.h>
#include <netdb.h>
#include <openssl/ssl.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <sys/time.h>
#include <sys/socket.h>
#include <pthread.h>
#include <getopt.h>
#include <debug.h>
#include <dpi.h>

#include "circuit.h"

#define FAIL    -1
#define MAX_THREADS 10

int dtype = DPI_DEBUG_INIT;
void *run(void *data);
int open_connection(const char *hostname, int port);
SSL_CTX* init_client_CTX(void);
void load_certificates(SSL_CTX* ctx, char* cert_file, char* key_file);
SSL_CTX *ctx;
const char *hostname, *portnum;

typedef struct arg_st {
  char *host;
  int port;
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
  emsg("  -h, --host           hostname");
  emsg("  -p, --port           port number");
  emsg("  -n, --nthreads       number of threads");
  exit(1);
}

int main(int argc, char *argv[])
{   
	int i, c, rc, port, num_of_threads;
  char *pname, *host, *opt;

  pname = argv[0];
  host = NULL;
  port = -1;
  num_of_threads = 1;

  while (1)
  {
    int opt_idx = 0;
    static struct option long_options[] = {
      {"host", required_argument, 0, 'h'},
      {"port", required_argument, 0, 'p'},
      {"nthreads", required_argument, 0, 'n'},
      {0, 0, 0, 0}
    };

    opt = "h:p:n:0";

    c = getopt_long(argc, argv, opt, long_options, &opt_idx);

    if (c == -1)
      break;

    switch (c)
    {
      case 'h':
        host = optarg;
        break;
      case 'p':
        port = atoi(optarg);
        break;
      case 'n':
        num_of_threads = atoi(optarg);
        break;
      default:
        usage(pname);
    }
  }
  
  if (!host)
  {
    emsg("Host name is not set");
    usage(pname);
  }

  if (port < 0)
  {
    emsg("Port number is not set");
    usage(pname);
  }

  assert(host);
  imsg(DPI_DEBUG_INIT, "Host: %s", host);
  assert(port > 0 && port < 65536);
  imsg(DPI_DEBUG_INIT, "Port: %d", port);
  assert(num_of_threads > 0 && num_of_threads < MAX_THREADS);

	pthread_t thread[num_of_threads];
	pthread_attr_t attr;
  arg_t args[num_of_threads];
	pthread_attr_init(&attr);
	pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_JOINABLE);
	void *status;

  //SSL_library_init();
  //ctx = init_client_CTX();

	for (i=0; i<num_of_threads; i++)
	{
    args[i].host = host;
    args[i].port = port;
		rc = pthread_create(&thread[i], &attr, run, &args[i]);

		if (rc)
		{
			emsg("return code from pthread_create: %d", rc);
			return 1;
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
	//SSL_CTX_free(ctx);

  return 0;
}

void *run(void *data)
{	
  arg_t *arg;
  char *host;
	int sock, port, nrules, clen, bsize;
  uint8_t a, b, c;
  uint8_t *cert;
  char buf[BUF_SIZE] = {0};
  unsigned long start, end;

  arg = (arg_t *)data;
  host = arg->host;
  port = arg->port;
  nrules = 0;
  bsize = 16;

	sock = open_connection(host, port);

  ferret_random_ot(DPI_ROLE_CLIENT, sock, &a, &b, &c);

  start = get_current_clock_time();
  while (1)
  {
    read(sock, buf, 1);
    if (buf[0] == FALSE)
      break;
    nrules++;
    clen = read(sock, buf, bsize);
    cert = buf;
    iprint(DPI_DEBUG_INIT, "Certificate", cert, 0, clen, clen);
    circuit_randomization(DPI_ROLE_CLIENT, sock, CIRCUIT_TYPE_AES, a, b, c, cert, clen, 
        NULL, 0, NULL, 0);
  }
  end = get_current_clock_time();
  imsg(DPI_DEBUG_INIT, "start: %lu, end: %lu", start, end);
  imsg(DPI_DEBUG_INIT, "Elapsed time for %d rules: %.2f ms", nrules, (end - start) * 1.0 / nrules / 1000000);
  imsg(DPI_DEBUG_INIT, "End of the S's thread: %d", sock);
	close(sock);
  return NULL;
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

SSL_CTX* init_client_CTX(void)
{   
  SSL_METHOD *method;
  SSL_CTX *ctx;
        
  OpenSSL_add_all_algorithms(); 
  SSL_load_error_strings();
  method = (SSL_METHOD *)TLS_client_method();
  ctx = SSL_CTX_new(method);
  
  if ( ctx == NULL )
  {
    ERR_print_errors_fp(stderr);
    abort();
  }

  return ctx;
}
 
void load_certificates(SSL_CTX* ctx, char* cert_file, char* key_file)
{
	if ( SSL_CTX_load_verify_locations(ctx, NULL, "/etc/ssl/certs") != 1)
	{
		ERR_print_errors_fp(stderr);
		abort();
	}
	else
  {
		imsg(DPI_DEBUG_INIT, "SSL_CTX_load_verify_locations success");
  }

	if ( SSL_CTX_set_default_verify_paths(ctx) != 1)
	{
		ERR_print_errors_fp(stderr);
		abort();
	}
	else
  {
		imsg(DPI_DEBUG_INIT, "SSL_CTX_set_default_verify_paths success");
  }

  /* set the local certificate from CertFile */
  if ( SSL_CTX_use_certificate_file(ctx, cert_file, SSL_FILETYPE_PEM) <= 0 )
  {
    ERR_print_errors_fp(stderr);
    abort();
	}
  else
  {
		imsg(DPI_DEBUG_INIT, "SSL_CTX_use_certificate_file success");
  }

	/* set the private key from KeyFile (may be the same as CertFile) */
  if ( SSL_CTX_use_PrivateKey_file(ctx, key_file, SSL_FILETYPE_PEM) <= 0 )
  {
    ERR_print_errors_fp(stderr);
    abort();
  }
	else
  {
		imsg(DPI_DEBUG_INIT, "SSL_CTX_use_PrivateKey_file success");
  }
    
	/* verify private key */
  if ( !SSL_CTX_check_private_key(ctx) )
  {
    ERR_print_errors_fp(stderr);
    abort();
  }
	else
  {
	  imsg(DPI_DEBUG_INIT, "Private key matches the public certificate");
  }
}
