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
unsigned long get_current_clock_time_fc(void)
{
  struct timespec ts;
  clock_gettime(CLOCK_MONOTONIC, &ts);
  return ts.tv_sec * 1000000000 + ts.tv_nsec;
}
#endif /* INTERNAL */

etoken_t *fixedkey_cluster_token_encryption(dpi_t *dpi, token_t *token)
{
	fstart("dpi: %p, token: %p", dpi, token);
	assert(dpi != NULL);

  int i, rc, hlen, elen, rs, sklen, cvalue, bsize, max_num_of_fetched, num_of_clusters;
  uint8_t cid;
  uint64_t salt;
  uint8_t *skey;
  uint8_t hval[16] = {0, };
  uint8_t eval[16] = {0, };
  uint8_t sbuf[16] = {0, };
  uint8_t tmp[16] = {0, };
  etoken_t *ret;
  security_context_t *context;
  counter_table_t *table;
  EVP_CIPHER_CTX *ectx;
  const EVP_CIPHER *eevp;
#ifdef INTERNAL
  unsigned long start[10], end[10], tstart, tend;
  int idx = 0;
#endif /* INTERNAL */

#ifdef INTERNAL
  tstart = start[idx] = get_current_clock_time_fc();
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
  skey = get_context_secret(context, &sklen);
  assert(skey != NULL);
  salt = get_context_salt(context);
  rs = get_context_rs_value(context);
  assert(rs > 0);
  bsize = get_context_block_size(context);
#ifdef INTERNAL
  end[idx++] = get_current_clock_time_fc();
#endif /* INTERNAL */

  dmsg(DPI_DEBUG_MIDDLEBOX, "Token Value to be Encrypted (%d bytes): %s", (token->len), (token->value));

#ifdef INTERNAL
  start[idx] = get_current_clock_time_fc();
#endif /* INTERNAL */
  for (i=0; i<bsize; i++)
    tmp[i] = (token->value)[i] ^ skey[i];
#ifdef INTERNAL
  end[idx++] = get_current_clock_time_fc();
#endif /* INTERNAL */

#ifdef INTERNAL
  start[idx] = get_current_clock_time_fc();
#endif /* INTERNAL */
  rc = EVP_EncryptUpdate(ectx, hval, &hlen, tmp, bsize);
#ifdef INTERNAL
  end[idx++] = get_current_clock_time_fc();
#endif /* INTERNAL */
  assert(rc == 1);

  // tmp -> skey
#ifdef INTERNAL
  start[idx] = get_current_clock_time_fc();
#endif /* INTERNAL */
  for (i=0; i<bsize; i++)
    hval[i] = hval[i] ^ skey[i];
#ifdef INTERNAL
  end[idx++] = get_current_clock_time_fc();
#endif /* INTERNAL */

#ifdef INTERNAL
  start[idx] = get_current_clock_time_fc();
#endif /* INTERNAL */
  cid = hval[0] % num_of_clusters;
  cvalue = get_counter_table_cvalue(table, cid);
#ifdef INTERNAL
  end[idx++] = get_current_clock_time_fc();
#endif /* INTERNAL */

#ifdef INTERNAL
  start[idx] = get_current_clock_time_fc();
#endif /* INTERNAL */
  salt += cvalue;
  VAR_TO_PTR_8BYTES(salt, sbuf);
  check_counter_table_num_of_fetched(table, cid, max_num_of_fetched);
#ifdef INTERNAL
  end[idx++] = get_current_clock_time_fc();
#endif /* INTERNAL */

#ifdef INTERNAL
  start[idx] = get_current_clock_time_fc();
#endif /* INTERNAL */
  for (i=0; i<bsize; i++)
    tmp[i] = hval[i] ^ sbuf[i];
#ifdef INTERNAL
  end[idx++] = get_current_clock_time_fc();
#endif /* INTERNAL */

#ifdef INTERNAL
  start[idx] = get_current_clock_time_fc();
#endif /* INTERNAL */
  rc = EVP_EncryptUpdate(ectx, eval, &elen, tmp, bsize);
#ifdef INTERNAL
  end[idx++] = get_current_clock_time_fc();
#endif /* INTERNAL */
  assert(rc == 1);

  // tmp -> hval
#ifdef INTERNAL
  start[idx] = get_current_clock_time_fc();
#endif /* INTERNAL */
  for (i=0; i<bsize; i++)
    eval[i] = eval[i] ^ hval[i];
#ifdef INTERNAL
  end[idx++] = get_current_clock_time_fc();
#endif /* INTERNAL */

#ifdef INTERNAL
  start[idx] = get_current_clock_time_fc();
#endif /* INTERNAL */
  ret = init_etoken(eval, rs);
  set_etoken_cid(ret, cid);
#ifdef INTERNAL
  tend = end[idx++] = get_current_clock_time_fc();
#endif /* INTERNAL */
  print_interval("others 1", start[0], end[0]);
  print_interval("xor 1", start[1], end[1]);
  print_interval("aes 1", start[2], end[2]);
  print_interval("xor 2", start[3], end[3]);
  print_interval("counter value", start[4], end[4]);
  print_interval("others 2", start[5], end[5]);
  print_interval("xor 3", start[6], end[6]);
  print_interval("aes 2", start[7], end[7]);
  print_interval("xor 4", start[8], end[8]);
  print_interval("others 3", start[9], end[9]);
  print_interval("total", tstart, tend);
#ifdef INTERNAL
  printf("\n");
#endif /* INTERNAL */

	ffinish("ret: %p", ret);
	return ret;
}
