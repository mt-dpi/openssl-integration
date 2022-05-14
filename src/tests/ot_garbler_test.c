#include <dpi/oblivious_transfer.h>
#include <dpi/debug.h>
#include <dpi/defines.h>

#include <getopt.h>
#include <unistd.h>
#include <stdlib.h>
#include <resolv.h>
#include <netdb.h>
#include <time.h>
#include <sys/time.h>
#include <sys/socket.h>

#include <openssl/evp.h>

#define PRIME_BITS 1024

int open_connection(const char *hostname, int port);

int usage(const char *pname)
{
  emsg(">> Usage: %s [options]", pname);
  emsg("Options");
  emsg("  -h, --host        Host to be connected");
  emsg("  -p, --port        Port number to be connected");
  exit(1);
}

int main(int argc, char *argv[])
{
  int c, ret, dtype, sock, port;
  const char *pname, *cname, *host;
  ot_t *ot;
  unsigned long start, end;
  const char *msg0 = "hello!";
  const char *msg1 = "world!";

  pname = argv[0];
  host = NULL;
  dtype = DPI_DEBUG_CIRCUIT;
  port = -1;

  while (1)
  {
    int option_index = 0;
    static struct option long_options[] = {
      {"circuit", required_argument, 0, 'c'},
      {"host", required_argument, 0, 'h'},
      {"port", required_argument, 0, 'p'},
      {0, 0, 0, 0}
    };

    const char *opt = "c:h:p:0";

    c = getopt_long(argc, argv, opt, long_options, &option_index);

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
  imsg(DPI_DEBUG_CIRCUIT, "Host: %s", host);
  assert(port > 0 && port < 65536);
  imsg(DPI_DEBUG_CIRCUIT, "Port: %d", port);
  
  sock = open_connection(host, port);
  ot = init_ot(PRIME_BITS, NULL, NULL, NULL);
  ret = send_ot_params(sock, ot);

  send_ot_message(sock, ot, msg0, strlen(msg0), msg1, strlen(msg1));

  free_ot(ot);

  return 0;
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
  memset(&addr, 0, sizeof(addr));
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

