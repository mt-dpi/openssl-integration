#include <dpi/debug.h>
#include <dpi/defines.h>
#include "token_encryptor_local.h"

#include <openssl/evp.h>

#include "../dpi_local.h"
#include "../etc/security_context.h"
#include "../etc/counter_table.h"
#include "../etc/pbytes.h"

#ifdef INTERNAL
  #define print_interval(m, a, b) \
    printf("%s: %lu ns\n", m, b - a);
#else
  #define print_interval(m, a, b)
#endif /* INTERNAL */

#ifdef INTERNAL
unsigned long get_current_clock_time_ng(void)
{
  struct timespec ts;
  clock_gettime(CLOCK_MONOTONIC, &ts);
  return ts.tv_sec * 1000000000 + ts.tv_nsec;
}
#endif /* INTERNAL */

etoken_t *nonfixedkey_global_token_encryption(dpi_t *dpi, token_t *token)
{
  fstart("dpi: %p, token: %p", dpi, token);

  int rc, etlen, elen, rs, count, bsize, max_num_of_fetched;
  uint64_t salt;
  uint8_t etkey[16] = {0, };
  uint8_t enc[16] = {0, };
  uint8_t sbuf[16] = {0, };
  etoken_t *ret;
  security_context_t *context;
  counter_table_t *table;
  EVP_CIPHER_CTX *ectx, *etctx;
  const EVP_CIPHER *eevp;
#ifdef INTERNAL
  unsigned long start[10], end[10], tstart, tend;
  int idx = 0;
#endif /* INTERNAL */

#ifdef INTERNAL
  tstart = start[idx] = get_current_clock_time_ng();
#endif /* INTERNAL */
  context = dpi_get_security_context(dpi);
  table = dpi_get_counter_table(dpi);
#ifdef INTERNAL
  end[idx++] = get_current_clock_time_ng();
#endif /* INTERNAL */

#ifdef INTERNAL
  start[idx] = get_current_clock_time_ng();
#endif /* INTERNAL */
  count = get_counter_table_cvalue(table, 0);
#ifdef INTERNAL
  end[idx++] = get_current_clock_time_ng();
#endif /* INTERNAL */

#ifdef INTERNAL
  start[idx] = get_current_clock_time_ng();
#endif /* INTERNAL */
  max_num_of_fetched = dpi_get_max_num_of_fetched(dpi);

  ectx = get_context_encryption_context(context);
  assert(ectx != NULL);
  eevp = get_context_cipher_algorithm(context);
  assert(eevp != NULL);
  salt = get_context_salt(context);
  rs = get_context_rs_value(context);
  assert(rs > 0);
  bsize = get_context_block_size(context);
#ifdef INTERNAL
  end[idx++] = get_current_clock_time_ng();
#endif /* INTERNAL */

  dmsg(DPI_DEBUG_MIDDLEBOX, "Token Value to be Encrypted (%d bytes): %s", (token->len), (token->value));
#ifdef INTERNAL
  start[idx] = get_current_clock_time_ng();
#endif /* INTERNAL */
  //iprint(DPI_DEBUG_MIDDLEBOX, "token", (token->value), 0, (token->len), 16);
  imsg(DPI_DEBUG_MIDDLEBOX, "token length: %d", token->len);
  rc = EVP_EncryptUpdate(ectx, etkey, &etlen, token->value, token->len);
#ifdef INTERNAL
  end[idx++] = get_current_clock_time_ng();
#endif /* INTERNAL */
  assert(rc == 1);

  dprint(DPI_DEBUG_MIDDLEBOX, "DPIEnc Key", etkey, 0, etlen, 16);

#ifdef INTERNAL
  start[idx] = get_current_clock_time_ng();
#endif /* INTERNAL */
  etctx = EVP_CIPHER_CTX_new();
  rc = EVP_EncryptInit_ex(etctx, eevp, NULL, etkey, NULL);
#ifdef INTERNAL
  end[idx++] = get_current_clock_time_ng();
#endif /* INTERNAL */

  assert(rc == 1);

#ifdef INTERNAL
  start[idx] = get_current_clock_time_ng();
#endif /* INTERNAL */
  salt += count;
  VAR_TO_PTR_8BYTES(salt, sbuf);
  check_counter_table_num_of_fetched(table, 0, max_num_of_fetched);
#ifdef INTERNAL
  end[idx++] = get_current_clock_time_ng();
#endif /* INTERNAL */

#ifdef INTERNAL
  start[idx] = get_current_clock_time_ng();
#endif /* INTERNAL */
  rc = EVP_EncryptUpdate(etctx, enc, &elen, sbuf, bsize);
#ifdef INTERNAL
  end[idx++] = get_current_clock_time_ng();
#endif /* INTERNAL */
  assert(rc == 1);

  dprint(DPI_DEBUG_MIDDLEBOX, "DPIEnc Result", enc, 0, elen, 16);
#ifdef INTERNAL
  start[idx] = get_current_clock_time_ng();
#endif /* INTERNAL */
  ret = init_etoken(enc, rs);

//  if (!count)
//    free_token(token);
#ifdef INTERNAL
  tend = end[idx++] = get_current_clock_time_ng();
#endif /* INTERNAL */
  print_interval("others 1", start[0], end[0]);
  print_interval("counter value", start[1], end[1]);
  print_interval("others 2", start[2], end[2]);
  print_interval("aes 1", start[3], end[3]);
  print_interval("aes init", start[4], end[4]);
  print_interval("others 3", start[5], end[5]);
  print_interval("aes 2", start[6], end[6]);
  print_interval("others 4", start[7], end[7]);
  print_interval("total", tstart, tend);

#ifdef INTERNAL
  printf("\n");
#endif /* INTERNAL */

  ffinish("ret: %p", ret);
  return ret;
}
