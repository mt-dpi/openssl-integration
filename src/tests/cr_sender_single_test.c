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

#include <dpi/dpi.h>
#include <dpi/debug.h>
#include <dpi/circuit_randomization.h>

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
  const char *cname;
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
  emsg("  -c, --circuit        circuit");
  emsg("  -h, --host           hostname");
  emsg("  -p, --port           port number");
  emsg("  -n, --nthreads       number of threads");
  exit(1);
}

int main(int argc, char *argv[])
{   
	int i, c, rc, port, num_of_threads;
  char *pname, *cname, *host, *opt;

  pname = argv[0];
  cname = host = NULL;
  port = -1;
  num_of_threads = 1;

  while (1)
  {
    int opt_idx = 0;
    static struct option long_options[] = {
      {"circuit", required_argument, 0, 'c'},
      {"host", required_argument, 0, 'h'},
      {"port", required_argument, 0, 'p'},
      {"nthreads", required_argument, 0, 'n'},
      {0, 0, 0, 0}
    };

    opt = "c:h:p:n:0";

    c = getopt_long(argc, argv, opt, long_options, &opt_idx);

    if (c == -1)
      break;

    switch (c)
    {
      case 'c':
        cname = optarg;
        if (access(cname, F_OK) != 0)
        {
          emsg("The circuit file %s does not exist", cname);
          cname = NULL;
        }
        break;

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

  if (!cname)
  {
    emsg("Input circuit file should be inserted");
    usage(pname);
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
    args[i].cname = cname;
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
	int sock, port, nrules, bsize, tbr, rcvd, offset;
  uint8_t a, b, c;
  uint8_t *cert;
  const char *cname;
  sender_input_t *input;
  unsigned long start, end;

  arg = (arg_t *)data;
  host = arg->host;
  port = arg->port;
  cname = arg->cname;
  nrules = 0;
  //bsize = 1;
  bsize = 16;

  // Test Reason
  input = (sender_input_t *)calloc(1, sizeof(sender_input_t));
  input->cname = cname;
  input->pkey = (uint8_t *)calloc(bsize, sizeof(uint8_t));
  //*(input->pkey) = 0x00;
  input->plen = bsize;
  input->skey = (uint8_t *)calloc(bsize, sizeof(uint8_t));
  //*(input->skey) = 0xc9;
  input->slen = bsize;

	sock = open_connection(host, port);

  fernet_random_ot(DPI_ROLE_CLIENT, sock, &a, &b, &c);

  cert = (uint8_t *)calloc(bsize, sizeof(uint8_t *));
  tbr = bsize;
  offset = 0;
  while (offset < tbr)
  {
    rcvd = read(sock, cert+offset, bsize-offset);
    offset += rcvd;
  }
  assert(offset == rcvd);

  start = get_current_clock_time();
  input->cert = cert;
  input->clen = bsize;
  circuit_randomization(DPI_ROLE_CLIENT, sock, a, b, c, input);
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
