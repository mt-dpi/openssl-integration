#include <stdio.h>
#include <errno.h>
#include <unistd.h>
#include <malloc.h>
#include <string.h>
#include <time.h>
#include <resolv.h>
#include <netdb.h>
#include <getopt.h>
#include <sys/time.h>
#include <sys/socket.h>
#include <netinet/tcp.h>
#include <fcntl.h>

#include <dpi/debug.h>
#include <dpi/association_table.h>
#include <dpi/dpi.h>
#include <dpi/token.h>
#include <dpi/circuit_randomization.h>

#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/rand.h>

#include "errors.h"

#define MAX_CLNT_SIZE 1000
#define MAX_THREADS 100
#define KEYWORD_SIZE  8
#define BLOCK_SIZE    16
#define TLS_RECORD_HEADER_LENGTH 5
#define MB_BUF_SIZE 83840

#define FAIL    -1

int open_listener(int port);
int open_connection(const char *hostname, int port);
SSL_CTX *init_middlebox_ctx(void);
void load_certificates(SSL_CTX *ctx, const char *cert, const char *pkey, const char *cacert);
void *mb_main(void *data);
void *mb_run(void *data);
void *forwarder_run(void *data);
int dtype;
unsigned long cstart, cend;

unsigned long get_current_time(void);
unsigned long get_current_cpu(void);
pthread_t threads[MAX_THREADS];
pthread_attr_t attr;
int complete[MAX_THREADS];
int tidx;

typedef struct info_st
{
  int mclient;
  int mserver;
  int smb;
  int cestablished;
  int sestablished;

  SSL_CTX *ctx;
  association_table_t *table;
  int init;
  int loop;

  int s2c;
  int c2s;
  int len;
  int inspection;
  int result;
} info_t;

typedef struct slave_st
{
  int sock;
  info_t *info;
} slave_t;

int usage(const char *pname)
{
  emsg(">> Usage: %s [options]", pname);
  emsg("Options");
  emsg("  -1, --port        Middlebox Listening Port Number");
  emsg("  -2, --cert        Middlebox Certificate");
  emsg("  -3, --key         Private Key");
  emsg("  -4, --cacert      CA Certificate");
  emsg("  -5, --forwarding-port     Forwarding Port");
  emsg("  -a, --rule-preparation    Rule Preparation");
  emsg("  -b, --get-next-token      Get Next Token");
  emsg("  -c, --token-encryption    Token Encryption");
  emsg("  -d, --token-detection     Token Detection");
  emsg("  -e, --tree-update         Tree Update");
  emsg("  -n, --name                DPI Name");
  emsg("  -r, --rule                Rule Filename");
  emsg("  -l, --logging             Enable Logging");
  emsg("  -t, --local-test          Local Test");
  emsg("  -k, --use-hardcoded-keys  Use Hardcoded Keys");
  emsg("  -u, --num-of-trees        Number of Trees");
  emsg("  -w, --window-size         Window Size");
  emsg("  -s, --token-size          Token Size");
  emsg("  -y, --clustering          Enable Clustering Rules");
  emsg("  -z, --num-of-clusters     Number of Clusters");
  emsg("  -f, --max-num-of-fetched  Maximum Number of Fetched");
  emsg("  -j, --use-tree-updater    Use tree updater");
  emsg("  -q, --prev-num-of-entries Num of Entries Inserted in a Counter Table");
  emsg("  -x, --enforce-init        Enforce to Perform the Initialization Step");

  exit(1);
}

int main(int argc, char *argv[])
{  
	int i, forwarder, mb, client, rc, mport, sport, err, c, init;
  int rpidx, tnidx, teidx, tdidx, tuidx, wlen, tlen, flags, clustering, nc, nt, mf, ne;
	const char *pname, *cert, *pkey, *cacert;
  char *name, *rname, *lname, *hname, *mname, *lprefix;
  void *status;
  association_table_t *table;
  handle_table_t *handles;
  conf_t *conf;
  SSL_CTX *ctx;

  tidx = 0;
  err = 0;
  pname = argv[0];
  cert = NULL;
  pkey = NULL;
  cacert = NULL;
  ctx = NULL;
  conf = NULL;

  name = NULL;
  rname = NULL;
  hname = NULL;

  lname = NULL;
  mname = NULL;
  lprefix = NULL;

  init = 0;

  clustering = FALSE;

  rpidx = -1;
  tnidx = -1;
  teidx = -1;
  tdidx = -1;
  tuidx = -1;
  wlen = -1;
  tlen = -1;
  flags = -1;
  nc = -1;
  nt = -1;
  mf = -1;
  forwarder = -1;

  mport = -1;
  sport = -1;

  dtype = DPI_DEBUG_MIDDLEBOX|DPI_DEBUG_LIBRARY;
  conf = init_conf_module();

  while (1)
  {
    int option_index = 0;
    static struct option long_options[] = {
      {"port", required_argument, 0, '1'},
      {"cert", required_argument, 0, '2'},
      {"key", required_argument, 0, '3'},
      {"cacert", required_argument, 0, '4'},
      {"forwarding-port", required_argument, 0, '5'},
      {"rule-preparation", required_argument, 0, 'a'},
      {"get-next-token", required_argument, 0, 'b'},
      {"token-encryption", required_argument, 0, 'c'},
      {"token-detection", required_argument, 0, 'd'},
      {"tree-update", required_argument, 0, 'e'},
      {"name", required_argument, 0, 'n'},
      {"rule-filename", required_argument, 0, 'r'},
      {"handle-filename", required_argument, 0, 'h'},
      {"logging", no_argument, 0, 'l'},
      {"log-directory", required_argument, 0, 'o'},
      {"log-prefix", required_argument, 0, 'p'},
      {"log-messages", required_argument, 0, 'm'},
      {"log-flags", required_argument, 0, 'f'},
      {"local-test", no_argument, 0, 't'},
      {"use-hardcoded-keys", no_argument, 0, 'k'},
      {"window-size", required_argument, 0, 'w'},
      {"token-size", required_argument, 0, 's'},
      {"clustering", no_argument, 0, 'y'},
      {"num-of-clusters", required_argument, 0, 'z'},
      {"num-of-trees", required_argument, 0, 'u'},
      {"max-num-of-fetched", required_argument, 0, 'g'},
      {"use-tree-updater", no_argument, 0, 'j'},
      {"prev-num-of-entries", required_argument, 0, 'q'},
      {"enforce-init", no_argument, 0, 'x'},
      {0, 0, 0, 0}
    };

    const char *opt = "1:2:3:4:5:a:b:c:d:e:n:r:h:lo:p:m:f:tkw:s:yz:u:g:jq:x0";

    c = getopt_long(argc, argv, opt, long_options, &option_index);

    if (c == -1)
      break;
    
    switch (c)
    {
      case '1':
        sport = atoi(optarg);
        break;

      case '2':
        cert = optarg;
        if (access(cert, F_OK) == -1)
          err |= ERR_INVALID_CERTIFICATE_PATH;
        break;

      case '3':
        pkey = optarg;
        if (access(pkey, F_OK) == -1)
          err |= ERR_INVALID_PRIVATE_KEY_PATH;
        break;

      case '4':
        cacert = optarg;
        if (access(cacert, F_OK) == -1)
          err |= ERR_INVALID_CA_CERTIFICATE_PATH;
        break;

      case '5':
        mport = atoi(optarg);
        break;

      case 'a':
        rpidx = atoi(optarg);
        set_conf_module_rule_preparation_idx(conf, rpidx);
        break;

      case 'b':
        tnidx = atoi(optarg);
        set_conf_module_get_next_token_idx(conf, tnidx);
        break;

      case 'c':
        teidx = atoi(optarg);
        set_conf_module_token_encryption_idx(conf, teidx);
        break;

      case 'd':
        tdidx = atoi(optarg);
        set_conf_module_token_detection_idx(conf, tdidx);
        break;

      case 'e':
        tuidx = atoi(optarg);
        set_conf_module_tree_update_idx(conf, tuidx);
        break;

      case 'n':
        name = optarg;
        set_conf_module_dpi_name(conf, name);
        break;

      case 'r':
        rname = optarg;
        set_conf_param_rule_filename(conf, rname);
        break;

      case 'h':
        hname = optarg;
        set_conf_param_handle_filename(conf, hname);
        break;

      case 'l':
        set_conf_log_enable_logging(conf);
        break;

      case 'o':
        lname = optarg;
        set_conf_log_directory(conf, lname);
        break;

      case 'p':
        lprefix = optarg;
        set_conf_log_prefix(conf, lprefix);
        break;

      case 'm':
        mname = optarg;
        set_conf_log_messages(conf, mname);
        break;

      case 'f':
        flags = atoi(optarg);
        set_conf_log_flags(conf, flags);
        break;

      case 't':
        set_conf_exp_local_test(conf);
        break;

      case 'k':
        set_conf_exp_use_hardcoded_keys(conf);
        break;

      case 'w':
        wlen = atoi(optarg);
        set_conf_param_window_size(conf, wlen);
        break;

      case 's':
        tlen = atoi(optarg);
        set_conf_param_token_size(conf, tlen);
        break;

      case 'u':
        nt = atoi(optarg);
        set_conf_param_num_of_trees(conf, nt);
        break;

      case 'y':
        set_conf_param_enable_clustering(conf);
        clustering = TRUE;
        break;

      case 'z':
        nc = atoi(optarg);
        set_conf_param_num_of_clusters(conf, nc);
        break;

      case 'g':
        mf = atoi(optarg);
        set_conf_param_max_num_of_fetched(conf, mf);
        break;

      case 'j':
        set_conf_exp_use_tree_updater(conf);
        break;

      case 'q':
        ne = atoi(optarg);
        set_conf_exp_prev_num_of_entries(conf, ne);
        break;

      case 'x':
        init = 1;
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

  if (mport < 0)
  {
    emsg("Please specify the port number of the forwarder to be connected");
    usage(pname);
  }

  if (sport < 0)
  {
    emsg("Please specify the port number of the server to be connected");
    usage(pname);
  }

  if (!name)
  {
    emsg("DPI name is not set");
    usage(pname);
  }

  if (!rname)
  {
    emsg("The rule filename is not set");
    usage(pname);
  }

  if (rpidx < 0)
  {
    emsg("The rule preparation function is not set");
    usage(pname);
  }

  if (tnidx < 0)
  {
    emsg("The tokenization function is not set");
    usage(pname);
  }

  if (teidx < 0)
  {
    emsg("The token encryption function is not set");
    usage(pname);
  }

  if (tdidx < 0)
  {
    emsg("The token detection function is not set");
    usage(pname);
  }

  if (tuidx < 0)
  {
    emsg("The tree update function is not set");
    usage(pname);
  }

  if (wlen < 0)
  {
    emsg("The window length is not set");
    usage(pname);
  }

  if (tlen < 0)
  {
    emsg("The encrypted token length is not set");
    usage(pname);
  }

  if (flags < 0)
  {
    emsg("The log flag is not set");
    usage(pname);
  }

  if (clustering && nc < 0)
  {
    emsg("The number of clusters should be set if clustering is enabled");
    usage(pname);
  }

  if (clustering && mf < 0)
  {
    emsg("The maximum number of fetched should be set if clustering is enabled");
    usage(pname);
  }

  if (clustering && (!(nt >= nc && nt % nc == 0)))
  {
    emsg("The number of trees should be multiple of the number of clusters if clustering is enabled");
    usage(pname);
  }

  if (err)
  {
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

	ctx = init_middlebox_ctx();        
  if (!init)
  {
    imsg(DPI_DEBUG_CIRCUIT, "Preparing the handle table from %s", hname);
    handles = dpi_prepare_handle_table(hname);
    assert(hname != NULL);
    SSL_CTX_mt_dpi_set_handle_table(ctx, handles);
  }
	load_certificates(ctx, cert, pkey, cacert);
  table = init_association_table(conf);

  pthread_attr_init(&attr);
  pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_JOINABLE);

  forwarder = open_listener(mport);
	mb = open_listener(sport);

	struct sockaddr_in maddr;
	socklen_t mlen = sizeof(maddr);

  imsg(DPI_DEBUG_CIRCUIT, "Listening connections at the forwarding port %d ...", mport);
  imsg(DPI_DEBUG_CIRCUIT, "Listening connections at the port %d ...", sport);
	while (1)
	{
    client = accept(forwarder, (struct sockaddr *)&maddr, &mlen);

    if (client < 0)
    {
      emsg("error in accept");
      exit(EXIT_FAILURE);
    }

    info_t *info = (info_t *)calloc(1, sizeof(info_t));
    info->mclient = client;
    info->smb = mb;
    info->ctx = ctx;
    info->table = table;
    info->init = init;
    rc = pthread_create(&threads[tidx++], &attr, forwarder_run, info);

    if (rc < 0)
    {
      emsg("error in pthread create");
      exit(EXIT_FAILURE);
    }
  }

  pthread_attr_destroy(&attr);

  for (i=0; i<tidx; i++)
  {
    rc = pthread_join(threads[i], &status);

    if (rc)
    {
      emsg("error in join: %d", rc);
      return 1;
    }
  }

  if (table)
    free_association_table(table);
  if (ctx)
  	SSL_CTX_free(ctx);
  if (mb > 0)
  {
  	close(mb);
  }

	return 0;
}

int verify_hmac(uint8_t *buf, int len, int elen)
{
  int ret, tnum;
  unsigned int hlen;
  uint8_t *p, *h;
  uint8_t hmac[SHA256_DIGEST_LENGTH] = {0, };
  EVP_MD_CTX *ctx;

  p = buf;
  PTR_TO_VAR_2BYTES(p, tnum);
  h = p + tnum * elen;

  dprint(DPI_DEBUG_MIDDLEBOX, "Received", buf, 0, len, 16);
  dmsg(DPI_DEBUG_MIDDLEBOX, "# of Tokens: %d", tnum);

  ctx = EVP_MD_CTX_create();
  EVP_DigestInit(ctx, EVP_sha256());
  EVP_DigestUpdate(ctx, buf, 2 + tnum * elen);
  EVP_DigestFinal(ctx, hmac, &hlen);
  EVP_MD_CTX_free(ctx);

  dprint(DPI_DEBUG_MIDDLEBOX, "Generated HMAC", hmac, 0, hlen, 16);
  dprint(DPI_DEBUG_MIDDLEBOX, "Received HMAC", h, 0, hlen, 16);

  if (!strncmp((const char *)hmac, 
        (const char *)h, hlen))
  {
    dmsg(DPI_DEBUG_MIDDLEBOX, "HMAC is verified");
    ret = 1;
  }
  else
  {
    dmsg(DPI_DEBUG_MIDDLEBOX, "HMAC is not verified");
    ret = 0;
  }

  return ret;
}

int check_tls_record_header(uint8_t *buf, int len, int *type)
{
  assert(buf != NULL);
  assert(len == TLS_RECORD_HEADER_LENGTH);

  int major, minor, length;
  *type = buf[0];
  major = buf[1];
  minor = buf[2];
  length = (buf[3] & 0xff) << 8 | (buf[4] & 0xff);

  switch (*type)
  {
    case 20:
      dmsg(DPI_DEBUG_MIDDLEBOX, "  Type: Change Cipher Spec");
      break;

    case 21:
      dmsg(DPI_DEBUG_MIDDLEBOX, "  Type: Alert");
      break;

    case 22:
      dmsg(DPI_DEBUG_MIDDLEBOX, "  Type: Handshake");
      break;

    case 23:
      dmsg(DPI_DEBUG_MIDDLEBOX, "  Type: Application Data");
      break;

    case 24:
      dmsg(DPI_DEBUG_MIDDLEBOX, "  Type: Heartbeat");
      break;

    default:
      emsg("  Type: Unknown");
  }

  if (major == 0x03 && minor == 0x01)
  {
    dmsg(DPI_DEBUG_MIDDLEBOX, "  Version: TLS 1.0");
  }
  else if (major == 0x03 && minor == 0x02)
  {
    dmsg(DPI_DEBUG_MIDDLEBOX, "  Version: TLS 1.1");
  }
  else if (major == 0x03 && minor == 0x03)
  {
    dmsg(DPI_DEBUG_MIDDLEBOX, "  Version: TLS 1.2");
  }
  else
  {
    emsg("  Version: Unknown");
  }

  dmsg(DPI_DEBUG_MIDDLEBOX, "  Length: %d", length);

  return length;
}

int check_tls_record_trailer(uint8_t *buf, int len)
{
  assert(buf != NULL);
  assert(len > 0);

  int last, length;
  last = buf[len-1];

  length = len - (TLS_RECORD_HEADER_LENGTH + last + 1);

  return length;
}

void *forwarder_run(void *data)
{
  info_t *info;
  int i, rc, tbs, tbr, offset, rcvd, sent, flags, msock[2], type, slot;
  int running;
  unsigned char buf[MB_BUF_SIZE] = {0, };
  unsigned long tstart, tend, sum;
  unsigned long tresult[10];

  info = (info_t *)data;
  msock[0] = info->mclient;
  msock[1] = open_connection("www.mt-dpi.com", 5556);
  if (msock[1] < 0)
  {
    emsg("error in connect()");
    exit(EXIT_FAILURE);
  }

  info->mserver = msock[1];
  info->loop = 1;
  rc = pthread_create(&threads[tidx++], &attr, mb_main, info);
  if (rc)
  {
    emsg("error in pthread_create()");
    exit(EXIT_FAILURE);
  }
  
  flags = fcntl(msock[0], F_GETFL);
  fcntl(msock[0], F_SETFL, flags | O_NONBLOCK);

  flags = fcntl(msock[1], F_GETFL);
  fcntl(msock[1], F_SETFL, flags | O_NONBLOCK);

  running = 1;
  slot = 0;
	while (running)
	{
    for (i=0; i<2; i++)
    {
      rcvd = read(msock[i], buf, TLS_RECORD_HEADER_LENGTH);
      if (rcvd > 0)
      {
        if (rcvd < TLS_RECORD_HEADER_LENGTH)
        {
          tbr = TLS_RECORD_HEADER_LENGTH;
          offset = rcvd;
          while (offset < tbr)
          {
            rcvd = read(msock[i], buf + offset, TLS_RECORD_HEADER_LENGTH - offset);
            if (rcvd > 0)
              offset += rcvd;
          }
        }
      
        tbr = check_tls_record_header(buf, TLS_RECORD_HEADER_LENGTH, &type);
        offset = 0;
        while (offset < tbr)
        {
          rcvd = read(msock[i], buf + TLS_RECORD_HEADER_LENGTH + offset, tbr - offset);
          if (rcvd > 0)
            offset += rcvd;
        }

        if (i == 0 && info->cestablished)
        {
          printf("received %d bytes from a client, now send it to a server\n", offset);
          info->inspection = 1;
          info->len = offset - 17;
        }
        else if (i == 1 && info->sestablished && offset != 234)
        {
          printf("received %d bytes from a server, now send it to a client\n", offset);
          info->inspection = 1;
          info->len = offset - 17;
        }

        // TODO: Need to wait the result of the token inspection
        if (info->inspection)
        {
          printf("should be inspected\n");
          tstart = get_current_time();
          while (info->inspection) {}
          tend = get_current_time();
          tresult[slot++] = tend - tstart;
        }

        tbs = offset + TLS_RECORD_HEADER_LENGTH;
        offset = 0;
        while (offset < tbs)
        {
          sent = write(msock[1-i], buf + offset, tbs - offset);
          offset += sent;
        }

        if (offset == 53 + TLS_RECORD_HEADER_LENGTH)
        {
          if (i == 0)
            info->cestablished = 1;
          else if (i == 1)
            info->sestablished = 1;
        }
      }
      else if (rcvd == 0)
      {
        if (i == 0)
          printf("the connection with a client is disconnected\n");
        else
          printf("the connection with a server is disconnected\n");
        running = 0;
        break;
      }
    }
  }
  printf("the connection is disconnected\n");
  
  sum = 0;
  for (i=0; i<slot; i++)
  {
    printf("waiting time[%d] = %lu ns\n", i, tresult[i]);
    sum += tresult[i];
  }
  printf("total waiting time = %lu ns\n", sum);

  info->loop = 0;
  for (i=0; i<2; i++)
    close(msock[i]);

  return NULL;
}

void *mb_main(void *data)
{
  info_t *info;
  slave_t *slave;
  struct sockaddr_in saddr;
  socklen_t slen;
  int rc, client, mb;

  printf("mb_main() is initiated\n");
  info = (info_t *)data;
  mb = info->smb;

	while (info->loop)
	{
    client = accept(mb, (struct sockaddr *)&saddr, &slen);
    printf("accepted in mb_main()\n");

    if (client < 0)
    {
      emsg("error in accept");
      exit(EXIT_FAILURE);
    }

    slave = (slave_t *)malloc(sizeof(slave_t));
    slave->sock = client;
    slave->info = info;
    rc = pthread_create(&threads[tidx], &attr, mb_run, slave);

    if (rc < 0)
    {
      emsg("error in pthread create");
      exit(EXIT_FAILURE);
    }
  }
  printf("close the mb_main()\n");

  return NULL;
}

void *mb_run(void *data)
{
  slave_t *slave;
  info_t *info;
  uint8_t *key, *p;
  int client, klen, tlen, rcvd, ri, sidx, eidx, cnt, hit, verified, init, tbr, offset, tnum, hlen, flags;
  unsigned char buf[MB_BUF_SIZE];
  association_table_t *table;

  SSL *ssl;
  dpi_t *dpi;
  etoken_t *etoken;
  conf_t *conf;
  handle_table_t *handles;

  slave = (slave_t *)data;
  info = slave->info;
  client = slave->sock;
  table = info->table;
  init = info->init;
  conf = table->conf;
  tlen = get_conf_param_token_size(conf);
  hlen = 32;
  etoken = (etoken_t *)calloc(1, sizeof(etoken_t));

  ssl = SSL_new(info->ctx);
  SSL_set_fd(ssl, client);
  SSL_set_accept_state(ssl);
  SSL_mt_dpi_set_association_table(ssl, table);
  if (init)
    SSL_mt_dpi_enable_init(ssl);

  if (SSL_do_handshake(ssl) != 1)
  {
    imsg(DPI_DEBUG_MIDDLEBOX, "TLS channel is not established");
    goto out;
  }

  key = SSL_mt_dpi_get_association_key(ssl, &klen);
  dpi = get_associated_dpi_context(table, key, klen);
  if (init)
    dpi_rule_preparation(dpi);
  else
  {
    handles = SSL_mt_dpi_get_handle_table(ssl);
    if (handles)
    {
      imsg(DPI_DEBUG_MIDDLEBOX, "Load the previous handle table: dpi: %p, handles: %p", dpi, handles);
      dpi_set_handle_table(dpi, handles);
      dpi_rule_preparation(dpi);
      imsg(DPI_DEBUG_MIDDLEBOX, "Set the handle table complete");
    }
  }
  if (SSL_mt_dpi_is_server(ssl))
  {
    imsg(DPI_DEBUG_MIDDLEBOX, "TLS channel is established with TLS server");
    //info->sestablished = 1;
  }
  else
  {
    imsg(DPI_DEBUG_MIDDLEBOX, "TLS channel is established with TLS client");
    //info->cestablished = 1;
  }
  SSL_mt_dpi_set_complete(ssl);

  flags = fcntl(client, F_GETFL);
  fcntl(client, F_SETFL, flags | O_NONBLOCK);

  cnt = 0; hit = 0;
  while (1) 
  {
    tbr = 2;
    offset = 0;
    while (offset < tbr)
    {
      rcvd = SSL_read(ssl, buf, 2);
      if (rcvd > 0)
        offset += rcvd;
      else if (rcvd == 0)
      {
        emsg("the underlying socket is closed");
        goto out;
      }
    }
    assert(offset == tbr);
    p = buf;
    PTR_TO_VAR_2BYTES(p, tnum);

    tbr = tnum * tlen + hlen;
    offset = 0;
    while (offset < tbr)
    {
      rcvd = SSL_read(ssl, p+offset, tbr-offset);
      if (rcvd > 0)
        offset += rcvd;
      else if (rcvd == 0)
      {
        emsg("the underlying socket is closed");
        goto out;
      }
    }
    assert(offset == tbr);

    if (offset > 0)
    {
      if (SSL_mt_dpi_is_server(ssl))
      {
        imsg(DPI_DEBUG_MIDDLEBOX, "From Server> Received length (%d bytes)", rcvd);
      }
      else
      {
        imsg(DPI_DEBUG_MIDDLEBOX, "From Client> Received length (%d bytes)", rcvd);
      }
      verified = verify_hmac(buf, rcvd, tlen);
      if (!verified)
      {
        emsg("Incorrect HMAC received");
        //goto out;
      }

      for (sidx=0, eidx=tlen; eidx<rcvd; sidx+=tlen, eidx+=tlen)
      {
        update_etoken(etoken, buf + sidx, tlen); 
        cnt++;
        ri = dpi_token_detection(dpi, etoken);
        if (ri)
        {
          dmsg(DPI_DEBUG_MIDDLEBOX, "token detected");
          hit++;
        }
      }
      if (!hit)
      {
        printf("nothing is detected\n");
        while (!(info->inspection)) {}
        info->inspection = 0;
      }
      else
      {
        printf("something is detected\n");
        while (!(info->inspection)) {}
        info->inspection = 0;
      }
    }

    memset(buf, 0, MB_BUF_SIZE);
  }

out:
  //if (etoken)
  //  free(etoken);
  //if (ssl)
  //  SSL_free(ssl);
  close(client);
  return NULL;
}

int open_listener(int port)
{   int sd;
	struct sockaddr_in addr;

	sd = socket(PF_INET, SOCK_STREAM, 0);

	bzero(&addr, sizeof(addr));
	addr.sin_family = AF_INET;
	addr.sin_port = htons(port);
	addr.sin_addr.s_addr = INADDR_ANY;

  if (setsockopt(sd, SOL_SOCKET, SO_REUSEADDR, &(int){1}, sizeof(int)) < 0)
    perror("setsockopt(SO_REUSEADDR) failed");

//  if (setsockopt(sd, IPPROTO_TCP, TCP_NODELAY, &(int){1}, sizeof(int)) < 0)
//    perror("setsockopt(SO_REUSEADDR) failed");
  int flags = 0;
  if (setsockopt(sd, SOL_TCP, TCP_QUICKACK, &flags, sizeof(flags)) < 0)
    perror("setsockopt(SO_REUSEADDR) failed");


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

//  if (setsockopt(sd, IPPROTO_TCP, TCP_NODELAY, &(int){1}, sizeof(int)) < 0)
//    perror("setsockopt(SO_REUSEADDR) failed");
  int flags = 0;
  if (setsockopt(sd, SOL_TCP, TCP_QUICKACK, &flags, sizeof(flags)) < 0)
    perror("setsockopt(SO_REUSEADDR) failed");

  if ( connect(sd, (struct sockaddr*)&addr, sizeof(addr)) != 0 )
  {
    close(sd);
    perror(hostname);
    abort();
  }
         
  return sd;
}


SSL_CTX *init_middlebox_ctx(void)
{   
	SSL_METHOD *method;
  SSL_CTX *ctx;

	SSL_load_error_strings();
	//method = (SSL_METHOD *) TLS_mtdpi_server_method(); 
	method = (SSL_METHOD *) TLS_server_method(); 
	ctx = SSL_CTX_new(method);
	if (!ctx)
	{
		emsg("SSL_CTX init failed!");
		abort();
	}

  SSL_CTX_mt_dpi_set_middlebox(ctx);

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

