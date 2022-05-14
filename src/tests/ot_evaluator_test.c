#include <dpi/oblivious_transfer.h>
#include <dpi/debug.h>
#include <dpi/defines.h>

#include <getopt.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <pthread.h>
#include <time.h>
#include <sys/time.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <openssl/evp.h>

#define MAX_THREADS 10

int open_listener(int port);
void *run(void *data);

typedef struct arg_st {
  int client;
} arg_t;

int usage(const char *pname)
{
  emsg(">> Usage: %s [options]", pname);
  emsg("Options");
  emsg("  -p, --port     Port number");
  exit(1);
}

int main(int argc, char *argv[])
{
  int i, idx, c, rc, dtype, server, client, port;
  const char *pname;
  pthread_t thread[MAX_THREADS];
  pthread_attr_t attr;
  arg_t args[MAX_THREADS];
  void *status;

  srand(time(NULL));
  pname = argv[0];
  dtype = DPI_DEBUG_CIRCUIT;

  while (1)
  {
    int option_index = 0;
    static struct option long_options[] = {
      {"port", required_argument, 0, 'p'},
      {0, 0, 0, 0}
    };

    const char *opt = "p:0";

    c = getopt_long(argc, argv, opt, long_options, &option_index);

    if (c == -1)
      break;
    
    switch (c)
    {
      case 'p':
        port = atoi(optarg);
        break;

      default:
        usage(pname);
    }
  }

  if (port <= 0)
  {
    emsg("Port number is not set");
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
      imsg(DPI_DEBUG_CIRCUIT, "Accept a client: %d", client);

      if (idx < MAX_THREADS)
      {
        args[idx].client = client;
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

  for (i=0; i<MAX_THREADS; i++)
  {
    rc = pthread_join(thread[i], &status);

    if (rc)
    {
      emsg("return code from pthread_join: %d", rc);
      return 1;
    }
  }
  
	close(server);

  return 0;
}

void *run(void *data)
{
  int ret, len, sock, b;
  uint8_t buf[BUF_SIZE] = {0, };
  ot_t *ot;
  arg_t *arg;

  arg = (arg_t *)data;
  sock = arg->client;

  ot = receive_ot_params(sock);
  b = rand() % 2;
  receive_ot_message(sock, ot, b, buf, &len);
  dmsg(DPI_DEBUG_CIRCUIT, "Receive message (%d bytes): %s", len, buf);

  free_ot(ot);

out:
  return NULL;
}

int open_listener(int port)
{   
  int sd, option;
	struct sockaddr_in addr;
  option = 1;

	sd = socket(PF_INET, SOCK_STREAM, 0);
	setsockopt(sd, SOL_SOCKET, SO_REUSEADDR, &option, sizeof(option));

	memset(&addr, 0, sizeof(addr));
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

