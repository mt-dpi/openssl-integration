#include <dpi/garbled_circuit.h>
#include <dpi/gc_protocol.h>
#include <dpi/debug.h>
#include <dpi/defines.h>

#include <getopt.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <resolv.h>
#include <netdb.h>
#include <time.h>
#include <sys/time.h>
#include <sys/socket.h>

#include <openssl/evp.h>

#define PRIME_BITS 64
#define KEY_SIZE 16
#define BLOCK_SIZE 16

int open_connection(const char *hostname, int port);

int usage(const char *pname)
{
  emsg(">> Usage: %s [options]", pname);
  emsg("Options");
  emsg("  -c, --circuit     Circuit file path");
  emsg("  -h, --host        Host to be connected");
  emsg("  -p, --port        Port number to be connected");
  exit(1);
}

unsigned long get_current_clock_time(void)
{
  struct timespec ts;
  clock_gettime(CLOCK_MONOTONIC, &ts);
  return ts.tv_sec * 1000000000 + ts.tv_nsec;
}

int main(int argc, char *argv[])
{
  int c, ret, dtype, sock, port, elen;
  const char *pname, *cname, *host;
  garbled_circuit_t *gc;
  ot_t *ot;
  EVP_CIPHER_CTX *ectx;
  unsigned char msg[1] = { 0x00 };
  unsigned char key[KEY_SIZE] = 
  { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  };
  /*
  unsigned char msg[BLOCK_SIZE] = 
  { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfc, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  };
  */
  unsigned char enc[BLOCK_SIZE] = {0, };
  unsigned long start, end;

  pname = argv[0];
  cname = host = NULL;
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
      case 'c':
        cname = optarg;
        if (access(cname, F_OK) != 0)
        {
          emsg("The file %s does not exist", cname);
          cname = NULL;
        }
        break;

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
  imsg(DPI_DEBUG_CIRCUIT, "Host: %s", host);
  assert(port > 0 && port < 65536);
  imsg(DPI_DEBUG_CIRCUIT, "Port: %d", port);
  
  ectx = EVP_CIPHER_CTX_new();
  EVP_EncryptInit_ex(ectx, EVP_aes_128_ecb(), NULL, key, NULL);
  EVP_EncryptUpdate(ectx, enc, &elen, msg, BLOCK_SIZE);
  EVP_CIPHER_CTX_free(ectx);

  iprint(DPI_DEBUG_CIRCUIT, "Key", key, 0, KEY_SIZE, 16);
  iprint(DPI_DEBUG_CIRCUIT, "Input", msg, 0, BLOCK_SIZE, 16);
  iprint(DPI_DEBUG_CIRCUIT, "Ciphertext (EVP)", enc, 0, elen, 16);

  start = get_current_clock_time();
  gc = init_garbled_circuit(cname, GARBLED_CIRCUIT_GARBLER);
  ot = init_ot(PRIME_BITS, NULL, NULL, NULL);

  sock = open_connection(host, port);
  ret = send_garbled_circuit_info(sock, gc);
  ret = send_ot_params(sock, ot);
  ret = receive_confirmation(sock);
  ret = send_encrypted_input_and_keys(sock, gc, ot, msg, 1);
  //ret = send_encrypted_input_and_keys(sock, gc, ot, key, KEY_SIZE);
  ret = receive_result(sock, gc, ot);
  end = get_current_clock_time();
  imsg(DPI_DEBUG_CIRCUIT, "Elapsed Time: %lu ns", (end - start));

  //free_garbled_circuit(gc);

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

