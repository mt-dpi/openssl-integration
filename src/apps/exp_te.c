#include <dpi/dpi.h>
#include <dpi/debug.h>
#include <stdlib.h>
#include <stdio.h>
#include <getopt.h>
#include <string.h>
#include <unistd.h>
#include <getopt.h>
#include <emmintrin.h>
#include "../etc/token.h"
#include "../etc/counter_table.h"
#include "../etc/security_context.h"
#include "../etc/pbytes.h"

#define COUNT 1000000
#define COUNTD (1.0 * COUNT)
#define BLOCK_SIZE 16

#define print_interval(m, a, b) \
  printf("%s: %lu ns\n", m, b - a);

#define print_per_interval(m, a, b) \
  printf("%s: %.2f ns\n", m, (b - a)/COUNTD);

int dtype;

static inline unsigned long get_current_time(void)
{
  struct timespec ts;
  clock_gettime(CLOCK_MONOTONIC, &ts);
  return ts.tv_sec * 1000000000 + ts.tv_nsec;
}

static inline unsigned long get_current_cpu_time(void)
{
  struct timespec ts;
  clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &ts);
  return ts.tv_sec * 1000000000 + ts.tv_nsec;
}

static inline void ememxor(uint8_t dst[BLOCK_SIZE], const uint8_t *a, const uint8_t *b)
{
  uint64_t *s = (uint64_t *)(dst);
  const uint64_t *au = (const uint64_t *)(a);
  const uint64_t *bu = (const uint64_t *)(b);

  s[0] = au[0] ^ bu[0];
  s[1] = au[1] ^ bu[1];
}

static inline void memxorv(uint8_t dst[BLOCK_SIZE], const uint8_t *a, const uint8_t *b)
{
  __m128i v0, v1, v2;
  v0 = _mm_loadu_si128((__m128i *)a);
  v1 = _mm_loadu_si128((__m128i *)b);
  v2 = _mm_xor_si128(v0, v1);
  _mm_store_si128((__m128i *)dst, v2);
}

int main(int argc, char *argv[])
{
  dpi_t *dpi;
  conf_t *conf;
  uint8_t *buf;
  int c, fsize, i, nentries, sklen, count, rs, bsize, rc, hlen, elen, etlen;
  token_t *token;
  etoken_t *etoken, *ret;
  FILE *fp;
  const char *iname, *pname;
  unsigned long cstart, cend, tstart, tend;
  unsigned long cresult[2], tresult[2];

  security_context_t *context;
  counter_table_t *table;
  entry_t *entry;
  EVP_CIPHER_CTX *ectx, *etctx;
  const EVP_CIPHER *eevp;
  uint64_t salt;
  uint8_t *skey;
  uint8_t sbuf[16];
  uint8_t tmp[16];
  uint8_t hval[16];
  uint8_t eval[16];
  uint8_t enc[16];
  uint8_t etkey[16];

  pname = argv[0];
  dtype = DPI_DEBUG_LIBRARY;

  conf = init_conf_module();
  set_conf_module(conf, argc, argv);
  dpi = init_dpi_context(DPI_ROLE_MIDDLEBOX, conf);
  free_conf_module(conf);

  dpi_rule_preparation(dpi);
  sleep(1);

  nentries = get_conf_exp_prev_num_of_entries(conf);

  iname = dpi_get_input_filename(dpi);
  fp = fopen(iname, "r");
  if (fp)
  {
    fseek(fp, 0, SEEK_END);
    fsize = ftell(fp);
    rewind(fp);

    buf = (uint8_t *)malloc(fsize);
    fread(buf, 1, fsize, fp);

    fclose(fp);
  }

  dpi_add_message(dpi, buf, fsize);

  tstart = get_current_time();
  for (i=0; i<COUNT; i++)
  {
    token = dpi_get_next_token(dpi);
    etoken = dpi_token_encryption(dpi, token);
  }
  tend = get_current_time();
  print_interval("Time: get_next_token() + token_encryption()", tstart, tend);
  tresult[0] = tend - tstart;

  tstart = get_current_time();
  for (i=0; i<COUNT; i++)
    token = dpi_get_next_token(dpi);
  tend = get_current_time();
  print_interval("Time: get_next_token()", tstart, tend);
  tresult[1] = tend - tstart;

  printf("\nFixed key encryption (line-by-line) >>>\n");
  context = dpi_get_security_context(dpi);
  table = dpi_get_counter_table(dpi);
  entry = add_counter_table_token(table, token);
  ectx = get_context_encryption_context(context);
  eevp = get_context_cipher_algorithm(context);
  skey = get_context_secret(context, &sklen);
  salt = get_context_salt(context);
  rs = get_context_rs_value(context);
  count = entry->count++;
  salt += count;
  VAR_TO_PTR_8BYTES(salt, sbuf);
  bsize = get_context_block_size(context);

  tstart = get_current_time();
  for (i=0; i<COUNT; i++)
  {
    memxorv(tmp, (token->value), skey);
    rc = EVP_EncryptUpdate(ectx, hval, &hlen, tmp, bsize);
    memxorv(hval, hval, skey);
    memxorv(tmp, hval, sbuf);
    rc = EVP_EncryptUpdate(ectx, eval, &elen, tmp, bsize);
    memxorv(eval, eval, hval);
  }
  tend = get_current_time();
  print_interval("Time: Fixed key (Total)", tstart, tend);
  print_per_interval("Time: Fixed key;", tstart, tend);

  printf("\nNon-fixed key encryption (line-by-line) >>>\n");
  entry = add_counter_table_token(table, token);
  count = entry->count++;
  salt += count;
  VAR_TO_PTR_8BYTES(salt, sbuf);
  tstart = get_current_time();
  for (i=0; i<COUNT; i++)
  {
    rc = EVP_EncryptUpdate(ectx, etkey, &etlen, token->value, token->len);
    etctx = EVP_CIPHER_CTX_new();
    rc = EVP_EncryptInit_ex(etctx, eevp, NULL, etkey, NULL);
    rc = EVP_EncryptUpdate(etctx, enc, &elen, sbuf, bsize);
  }
  tend = get_current_time();
  print_interval("Time: Non-fixed key (Total)", tstart, tend);
  print_per_interval("Time: Non-fixed key", tstart, tend);

  free_dpi_context(dpi);
  return 0;
}
