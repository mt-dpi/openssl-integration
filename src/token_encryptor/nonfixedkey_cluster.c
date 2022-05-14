#include <dpi/debug.h>
#include <dpi/defines.h>
#include "token_encryptor.h"

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
unsigned long get_current_clock_time_nc(void)
{
  struct timespec ts;
  clock_gettime(CLOCK_MONOTONIC, &ts);
  return ts.tv_sec * 1000000000 + ts.tv_nsec;
}
#endif /* INTERNAL */

etoken_t *nonfixedkey_cluster_token_encryption(dpi_t *dpi, token_t *token)
{
	fstart("dpi: %p, token: %p", dpi, token);
	assert(dpi != NULL);

  int rc, etlen, elen, rs, cvalue, bsize, max_num_of_fetched, num_of_clusters;
  uint8_t cid;
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
  tstart = start[idx] = get_current_clock_time_nc();
#endif /* INTERNAL */
  ret = NULL;
  context = dpi_get_security_context(dpi);
  table = dpi_get_counter_table(dpi);
  num_of_clusters = dpi_get_num_of_clusters(dpi);
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
  end[idx++] = get_current_clock_time_nc();
#endif /* INTERNAL */

  dmsg(DPI_DEBUG_MIDDLEBOX, "Token Value to be Encrypted (%d bytes): %s", (token->len), (token->value));
#ifdef INTERNAL
  start[idx] = get_current_clock_time_nc();
#endif /* INTERNAL */
  rc = EVP_EncryptUpdate(ectx, etkey, &etlen, token->value, token->len);
#ifdef INTERNAL
  end[idx++] = get_current_clock_time_nc();
#endif /* INTERNAL */
  assert(rc == 1);

  dprint(DPI_DEBUG_MIDDLEBOX, "DPIEnc Key", etkey, 0, etlen, 16);

#ifdef INTERNAL
  start[idx] = get_current_clock_time_nc();
#endif /* INTERNAL */
  etctx = EVP_CIPHER_CTX_new();
  rc = EVP_EncryptInit_ex(etctx, eevp, NULL, etkey, NULL);
#ifdef INTERNAL
  end[idx++] = get_current_clock_time_nc();
#endif /* INTERNAL */
  assert(rc == 1);

#ifdef INTERNAL
  start[idx] = get_current_clock_time_nc();
#endif /* INTERNAL */
  cid = etkey[0] % num_of_clusters;
  cvalue = get_counter_table_cvalue(table, cid);
#ifdef INTERNAL
  end[idx++] = get_current_clock_time_nc();
#endif /* INTERNAL */

#ifdef INTERNAL
  start[idx] = get_current_clock_time_nc();
#endif /* INTERNAL */
  salt += cvalue;
  VAR_TO_PTR_8BYTES(salt, sbuf);
  check_counter_table_num_of_fetched(table, cid, max_num_of_fetched);
#ifdef INTERNAL
  end[idx++] = get_current_clock_time_nc();
#endif /* INTERNAL */

#ifdef INTERNAL
  start[idx] = get_current_clock_time_nc();
#endif /* INTERNAL */
  rc = EVP_EncryptUpdate(etctx, enc, &elen, sbuf, bsize);
#ifdef INTERNAL
  end[idx++] = get_current_clock_time_nc();
#endif /* INTERNAL */
  assert(rc == 1);

#ifdef INTERNAL
  start[idx] = get_current_clock_time_nc();
#endif /* INTERNAL */
  dprint(DPI_DEBUG_MIDDLEBOX, "DPIEnc Result", enc, 0, elen, 16);
  ret = init_etoken(enc, rs);
  set_etoken_cid(ret, cid);

//  if (!cvalue)
//    free_token(token);
#ifdef INTERNAL
  tend = end[idx++] = get_current_clock_time_nc();
#endif /* INTERNAL */
  print_interval("others 1", start[0], end[0]);
  print_interval("aes 1", start[1], end[1]);
  print_interval("aes init", start[2], end[2]);
  print_interval("counter value", start[3], end[3]);
  print_interval("others 2", start[4], end[4]);
  print_interval("aes 2", start[5], end[5]);
  print_interval("others 2", start[6], end[6]);
  print_interval("total", tstart, tend);

#ifdef INTERNAL
  printf("\n");
#endif /* INTERNAL */

	ffinish("ret: %p", ret);
	return ret;
}
