#include <dpi/dpi.h>
#include <dpi/debug.h>
#include <stdlib.h>
#include <stdio.h>
#include <getopt.h>
#include <string.h>
#include <unistd.h>
#include "../etc/token.h"
#include "../etc/counter_table.h"
#include "../etc/security_context.h"
#include "../etc/pbytes.h"

#define COUNT 100000
#define COUNTD (1.0 * COUNT)
#define BLOCK_SIZE 16

#define print_interval(m, a, b) \
  printf("%s: %lu ns\n", m, b - a);

#define print_per_interval(m, a, b) \
  printf("%s: %.2f ns\n", m, (b - a)/COUNTD);

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

static inline void ememxor3(uint8_t dst[BLOCK_SIZE], const uint8_t *a, 
    const uint8_t *b, const uint8_t *c)
{
  uint64_t *s = (uint64_t *)(dst);
  const uint64_t *au = (const uint64_t *)(a);
  const uint64_t *bu = (const uint64_t *)(b);
  const uint64_t *cu = (const uint64_t *)(c);

  s[0] = au[0] ^ bu[0] ^ cu[0];
  s[1] = au[1] ^ bu[1] ^ cu[1];
}

int main(int argc, char *argv[])
{
  dpi_t *dpi;
  conf_t *conf;
  uint8_t *buf;
  int fsize, i, nentries, sklen, count, rs, bsize, rc, hlen, elen, etlen;
  token_t *token;
  etoken_t *etoken, *ret;
  FILE *fp;
  const char *iname;
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

  //cstart = get_current_cpu_time();
  tstart = get_current_time();
  for (i=0; i<COUNTD; i++)
  {
    token = dpi_get_next_token(dpi);
    etoken = dpi_token_encryption(dpi, token);
  }
  tend = get_current_time();
  //cend = get_current_cpu_time();
  print_interval("Time: get_next_token() + token_encryption()", tstart, tend);
  //print_interval("CPU: get_next_token() + token_encryption()", cstart, cend);
  tresult[0] = tend - tstart;
  //cresult[0] = cend - cstart;

  //cstart = get_current_cpu_time();
  tstart = get_current_time();
  for (i=0; i<COUNT; i++)
    token = dpi_get_next_token(dpi);
  tend = get_current_time();
  //cend = get_current_cpu_time();
  print_interval("Time: get_next_token()", tstart, tend);
  //print_interval("CPU: get_next_token()", cstart, cend);
  tresult[1] = tend - tstart;
  //cresult[1] = cend - cstart;

  printf("\nFixed key encryption (line-by-line) >>>\n");
  //cstart = get_current_cpu_time();
  tstart = get_current_time();
  for (i=0; i<COUNT; i++)
    context = dpi_get_security_context(dpi);
  tend = get_current_time();
  //cend = get_current_cpu_time();
  print_per_interval("Time: context = dpi_get_security_context();", tstart, tend);
  //print_per_interval("CPU: context = dpi_get_security_context();", cstart, cend);

  //cstart = get_current_cpu_time();
  tstart = get_current_time();
  for (i=0; i<COUNT; i++)
    table = dpi_get_counter_table(dpi);
  tend = get_current_time();
  //cend = get_current_cpu_time();
  print_per_interval("Time: table = dpi_get_counter_table();", tstart, tend);
  //print_per_interval("CPU: table = dpi_get_counter_table();", cstart, cend);

  //cstart = get_current_cpu_time();
  tstart = get_current_time();
  for (i=0; i<COUNT; i++)
    entry = add_counter_table_token(table, token);
  tend = get_current_time();
  //cend = get_current_cpu_time();
  print_per_interval("Time: entry = add_counter_table_token();", tstart, tend);
  //print_per_interval("CPU: entry = add_counter_table_token();", cstart, cend);

  //cstart = get_current_cpu_time();
  tstart = get_current_time();
  for (i=0; i<COUNT; i++)
    count = entry->count++;
  tend = get_current_time();
  //cend = get_current_cpu_time();
  print_per_interval("Time: count = entry->count++", tstart, tend);
  //print_per_interval("CPU: count = entry->count++", cstart, cend);

  //cstart = get_current_cpu_time();
  tstart = get_current_time();
  for (i=0; i<COUNT; i++)
    ectx = get_context_encryption_context(context);
  tend = get_current_time();
  //cend = get_current_cpu_time();
  print_per_interval("Time: ectx = get_context_encryption_context();", tstart, tend);
  //print_per_interval("CPU: ectx = get_context_encryption_context();", cstart, cend);

  //cstart = get_current_cpu_time();
  tstart = get_current_time();
  for (i=0; i<COUNT; i++)
    eevp = get_context_cipher_algorithm(context);
  tend = get_current_time();
  //cend = get_current_cpu_time();
  print_per_interval("Time: eevp = get_context_cipher_algorithm();", tstart, tend);
  //print_per_interval("CPU: eevp = get_context_cipher_algorithm();", cstart, cend);

  //cstart = get_current_cpu_time();
  tstart = get_current_time();
  for (i=0; i<COUNT; i++)
    skey = get_context_secret(context, &sklen);
  tend = get_current_time();
  //cend = get_current_cpu_time();
  print_per_interval("Time: skey = get_context_secret();", tstart, tend);
  //print_per_interval("CPU: skey = get_context_secret();", cstart, cend);

  //cstart = get_current_cpu_time();
  tstart = get_current_time();
  for (i=0; i<COUNT; i++)
    salt = get_context_salt(context);
  tend = get_current_time();
  //cend = get_current_cpu_time();
  print_per_interval("Time: salt = get_context_salt();", tstart, tend);
  //print_per_interval("CPU: salt = get_context_salt();", cstart, cend);

  //cstart = get_current_cpu_time();
  tstart = get_current_time();
  for (i=0; i<COUNT; i++)
    salt += count;
  tend = get_current_time();
  //cend = get_current_cpu_time();
  print_per_interval("Time: salt += count;", tstart, tend);
  //print_per_interval("CPU: salt += count;", cstart, cend);

  //cstart = get_current_cpu_time();
  tstart = get_current_time();
  for (i=0; i<COUNT; i++)
    VAR_TO_PTR_8BYTES(salt, sbuf);
  tend = get_current_time();
  //cend = get_current_cpu_time();
  print_per_interval("Time: VAR_TO_PTR_8BYTES(salt, sbuf);", tstart, tend);
  //print_per_interval("CPU: VAR_TO_PTR_8BYTES(salt, sbuf);", cstart, cend);

  //cstart = get_current_cpu_time();
  tstart = get_current_time();
  for (i=0; i<COUNT; i++)
    rs = get_context_rs_value(context);
  tend = get_current_time();
  //cend = get_current_cpu_time();
  print_per_interval("Time: rs = get_context_rs_value(context);", tstart, tend);
  //print_per_interval("CPU: rs = get_context_rs_value(context);", cstart, cend);

  //cstart = get_current_cpu_time();
  tstart = get_current_time();
  for (i=0; i<COUNT; i++)
    bsize = get_context_block_size(context);
  tend = get_current_time();
  //cend = get_current_cpu_time();
  print_per_interval("Time: bsize = get_context_block_size(context);", tstart, tend);
  //print_per_interval("CPU: bsize = get_context_block_size(context);", cstart, cend);

  //cstart = get_current_cpu_time();
  tstart = get_current_time();
  for (i=0; i<COUNT; i++)
    ememxor(tmp, (token->value), skey);
  tend = get_current_time();
  //cend = get_current_cpu_time();
  print_per_interval("Time: ememxor(tmp, (token->value), skey);", tstart, tend);
  //print_per_interval("CPU: ememxor(tmp, (token->value), skey);", cstart, cend);

  //cstart = get_current_cpu_time();
  tstart = get_current_time();
  for (i=0; i<COUNT; i++)
    rc = EVP_EncryptUpdate(ectx, hval, &hlen, tmp, bsize);
  tend = get_current_time();
  //cend = get_current_cpu_time();
  print_per_interval("Time: rc = EVP_EncryptUpdate(ectx, hval, &hlen, tmp, bsize);", tstart, tend);
  //print_per_interval("CPU: rc = EVP_EncryptUpdate(ectx, hval, &hlen, tmp, bsize);", cstart, cend);

  //cstart = get_current_cpu_time();
  tstart = get_current_time();
  for (i=0; i<COUNT; i++)
    ememxor3(hval, hval, skey, sbuf);
  tend = get_current_time();
  //cend = get_current_cpu_time();
  print_per_interval("Time: ememxor3(hval, hval, skey, sbuf);", tstart, tend);
  //print_per_interval("CPU: ememxor3(hval, hval, skey, sbuf);", cstart, cend);

  //cstart = get_current_cpu_time();
  tstart = get_current_time();
  for (i=0; i<COUNT; i++)
    rc = EVP_EncryptUpdate(ectx, eval, &elen, tmp, bsize);
  tend = get_current_time();
  //cend = get_current_cpu_time();
  print_per_interval("Time: EVP_EncryptUpdate(ectx, eval, &elen, tmp, bsize);", tstart, tend);
  //print_per_interval("CPU: EVP_EncryptUpdate(ectx, eval, &elen, tmp, bsize);", cstart, cend);

  //cstart = get_current_cpu_time();
  tstart = get_current_time();
  for (i=0; i<COUNT; i++)
    ememxor(eval, eval, hval);
  tend = get_current_time();
  //cend = get_current_cpu_time();
  print_per_interval("Time: ememxor(eval, eval, hval);", tstart, tend);
  //print_per_interval("CPU: ememxor(eval, eval, hval);", cstart, cend);

  //cstart = get_current_cpu_time();
  tstart = get_current_time();
  for (i=0; i<COUNT; i++)
    ret = init_etoken(eval, rs);
  tend = get_current_time();
  //cend = get_current_cpu_time();
  print_per_interval("Time: ret = init_etoken(eval, rs);", tstart, tend);
  //print_per_interval("CPU: ret = init_etoken(eval, rs);", cstart, cend);

  printf("\nNon-fixed key encryption (line-by-line) >>>\n");
  tstart = get_current_time();
  for (i=0; i<COUNT; i++)
    context = dpi_get_security_context(dpi);
  tend = get_current_time();
  //cend = get_current_cpu_time();
  print_per_interval("Time: context = dpi_get_security_context();", tstart, tend);
  //print_per_interval("CPU: context = dpi_get_security_context();", cstart, cend);

  //cstart = get_current_cpu_time();
  tstart = get_current_time();
  for (i=0; i<COUNT; i++)
    table = dpi_get_counter_table(dpi);
  tend = get_current_time();
  //cend = get_current_cpu_time();
  print_per_interval("Time: table = dpi_get_counter_table();", tstart, tend);
  //print_per_interval("CPU: table = dpi_get_counter_table();", cstart, cend);

  //cstart = get_current_cpu_time();
  tstart = get_current_time();
  for (i=0; i<COUNT; i++)
    entry = add_counter_table_token(table, token);
  tend = get_current_time();
  //cend = get_current_cpu_time();
  print_per_interval("Time: entry = add_counter_table_token();", tstart, tend);
  //print_per_interval("CPU: entry = add_counter_table_token();", cstart, cend);

  //cstart = get_current_cpu_time();
  tstart = get_current_time();
  for (i=0; i<COUNT; i++)
    count = entry->count++;
  tend = get_current_time();
  //cend = get_current_cpu_time();
  print_per_interval("Time: count = entry->count++", tstart, tend);
  //print_per_interval("CPU: count = entry->count++", cstart, cend);

  //cstart = get_current_cpu_time();
  tstart = get_current_time();
  for (i=0; i<COUNT; i++)
    ectx = get_context_encryption_context(context);
  tend = get_current_time();
  //cend = get_current_cpu_time();
  print_per_interval("Time: ectx = get_context_encryption_context();", tstart, tend);
  //print_per_interval("CPU: ectx = get_context_encryption_context();", cstart, cend);

  //cstart = get_current_cpu_time();
  tstart = get_current_time();
  for (i=0; i<COUNT; i++)
    eevp = get_context_cipher_algorithm(context);
  tend = get_current_time();
  //cend = get_current_cpu_time();
  print_per_interval("Time: eevp = get_context_cipher_algorithm();", tstart, tend);
  //print_per_interval("CPU: eevp = get_context_cipher_algorithm();", cstart, cend);

  //cstart = get_current_cpu_time();
  tstart = get_current_time();
  for (i=0; i<COUNT; i++)
    salt = get_context_salt(context);
  tend = get_current_time();
  //cend = get_current_cpu_time();
  print_per_interval("Time: salt = get_context_salt();", tstart, tend);
  //print_per_interval("CPU: salt = get_context_salt();", cstart, cend);

  //cstart = get_current_cpu_time();
  tstart = get_current_time();
  for (i=0; i<COUNT; i++)
    rs = get_context_rs_value(context);
  tend = get_current_time();
  //cend = get_current_cpu_time();
  print_per_interval("Time: rs = get_context_rs_value(context);", tstart, tend);
  //print_per_interval("CPU: rs = get_context_rs_value(context);", cstart, cend);

  //cstart = get_current_cpu_time();
  tstart = get_current_time();
  for (i=0; i<COUNT; i++)
    bsize = get_context_block_size(context);
  tend = get_current_time();
  //cend = get_current_cpu_time();
  print_per_interval("Time: bsize = get_context_block_size(context);", tstart, tend);
  //print_per_interval("CPU: bsize = get_context_block_size(context);", cstart, cend);

  //cstart = get_current_cpu_time();
  tstart = get_current_time();
  for (i=0; i<COUNT; i++)
    rc = EVP_EncryptUpdate(ectx, etkey, &etlen, token->value, token->len);
  tend = get_current_time();
  //cend = get_current_cpu_time();
  print_per_interval("Time: rc = EVP_EncryptUpdate(ectx, etkey, &etlen, token->value, token->len);", tstart, tend);
  //print_per_interval("CPU: rc = EVP_EncryptUpdate(ectx, hval, &hlen, tmp, bsize);", cstart, cend);

  //cstart = get_current_cpu_time();
  tstart = get_current_time();
  for (i=0; i<COUNT; i++)
    etctx = EVP_CIPHER_CTX_new();
  tend = get_current_time();
  //cend = get_current_cpu_time();
  print_per_interval("Time: etctx = EVP_CIPHER_CTX_new();", tstart, tend);
  //print_per_interval("CPU: rc = EVP_EncryptUpdate(ectx, hval, &hlen, tmp, bsize);", cstart, cend);

  //cstart = get_current_cpu_time();
  tstart = get_current_time();
  for (i=0; i<COUNT; i++)
    rc = EVP_EncryptInit_ex(etctx, eevp, NULL, etkey, NULL);
  tend = get_current_time();
  //cend = get_current_cpu_time();
  print_per_interval("Time: rc = EVP_EncryptInit_ex(etctx, eevp, NULL, etkey, NULL);", tstart, tend);
  //print_per_interval("CPU: rc = EVP_EncryptUpdate(ectx, hval, &hlen, tmp, bsize);", cstart, cend);

  //cstart = get_current_cpu_time();
  tstart = get_current_time();
  for (i=0; i<COUNT; i++)
    salt += count;
  tend = get_current_time();
  //cend = get_current_cpu_time();
  print_per_interval("Time: salt += count;", tstart, tend);
  //print_per_interval("CPU: salt += count;", cstart, cend);

  //cstart = get_current_cpu_time();
  tstart = get_current_time();
  for (i=0; i<COUNT; i++)
    VAR_TO_PTR_8BYTES(salt, sbuf);
  tend = get_current_time();
  //cend = get_current_cpu_time();
  print_per_interval("Time: VAR_TO_PTR_8BYTES(salt, sbuf);", tstart, tend);
  //print_per_interval("CPU: VAR_TO_PTR_8BYTES(salt, sbuf);", cstart, cend);

  //cstart = get_current_cpu_time();
  tstart = get_current_time();
  for (i=0; i<COUNT; i++)
    rc = EVP_EncryptUpdate(etctx, enc, &elen, sbuf, bsize);
  tend = get_current_time();
  //cend = get_current_cpu_time();
  print_per_interval("Time: rc = EVP_EncryptUpdate(etctx, enc, &elen, sbuf, bsize);", tstart, tend);
  //print_per_interval("CPU: rc = EVP_EncryptUpdate(ectx, hval, &hlen, tmp, bsize);", cstart, cend);

  //cstart = get_current_cpu_time();
  tstart = get_current_time();
  for (i=0; i<COUNT; i++)
    ret = init_etoken(eval, rs);
  tend = get_current_time();
  //cend = get_current_cpu_time();
  print_per_interval("Time: ret = init_etoken(eval, rs);", tstart, tend);
  //print_per_interval("CPU: ret = init_etoken(eval, rs);", cstart, cend);

  printf("\nFixed-key encryption (full loop) >>>>>\n");
  tstart = get_current_time();
  for (i=0; i<COUNT; i++)
  {
    context = dpi_get_security_context(dpi);
    table = dpi_get_counter_table(dpi);
    entry = add_counter_table_token(table, token);
    count = entry->count++;
    ectx = get_context_encryption_context(context);
    eevp = get_context_cipher_algorithm(context);
    skey = get_context_secret(context, &sklen);
    salt = get_context_salt(context);
    salt += count;
    VAR_TO_PTR_8BYTES(salt, sbuf);
    rs = get_context_rs_value(context);
    bsize = get_context_block_size(context);
    ememxor(tmp, (token->value), skey);
    rc = EVP_EncryptUpdate(ectx, hval, &hlen, tmp, bsize);
    ememxor3(hval, hval, skey, sbuf);
    rc = EVP_EncryptUpdate(ectx, eval, &elen, tmp, bsize);
    ememxor(eval, eval, hval);
    ret = init_etoken(eval, rs);
  }
  tend = get_current_time();
  //cend = get_current_cpu_time();
  print_per_interval("Time: fixedkey encryption (loop)", tstart, tend);
  //print_per_interval("CPU: ret = init_etoken(eval, rs);", cstart, cend);

  printf("\nNon-fixed key encryption (loop) >>>\n");
  tstart = get_current_time();
  for (i=0; i<COUNT; i++)
  {
    context = dpi_get_security_context(dpi);
    table = dpi_get_counter_table(dpi);
    entry = add_counter_table_token(table, token);
    count = entry->count++;
    ectx = get_context_encryption_context(context);
    eevp = get_context_cipher_algorithm(context);
    salt = get_context_salt(context);
    rs = get_context_rs_value(context);
    bsize = get_context_block_size(context);
    rc = EVP_EncryptUpdate(ectx, etkey, &etlen, token->value, token->len);
    etctx = EVP_CIPHER_CTX_new();
    rc = EVP_EncryptInit_ex(etctx, eevp, NULL, etkey, NULL);
    salt += count;
    VAR_TO_PTR_8BYTES(salt, sbuf);
    rc = EVP_EncryptUpdate(etctx, enc, &elen, sbuf, bsize);
    ret = init_etoken(eval, rs);
  }
  tend = get_current_time();
  //cend = get_current_cpu_time();
  print_per_interval("Time: Non-fixed key encryption (loop);", tstart, tend);
  //print_per_interval("CPU: ret = init_etoken(eval, rs);", cstart, cend);

  printf("\nTotal Result >>>\n");
  printf("Time: %d token encryption(): %.lu ns\n", COUNT, (tresult[0] - tresult[1]));
  printf("Time: %d token encryption() per token: %.2lf ns\n", COUNT, (tresult[0] - tresult[1])/COUNTD);
  //printf("CPU: %d token encryption(): %.lu ns\n", COUNT, (cresult[0] - cresult[1]));
  //printf("CPU: %d token encryption() per token: %.2lf ns\n", COUNT, (cresult[0] - cresult[1])/COUNTD);

  free_dpi_context(dpi);
  return 0;
}
