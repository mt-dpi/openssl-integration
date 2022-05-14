#include <dpi/debug.h>
#include <dpi/defines.h>
#include <limits.h>
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

#define BLKSIZE 16
#if UINT_MAX == 18446744073709551615ULL
typedef unsigned int big64_t;
#elif ULONG_MAX == 18446744073709551615ULL
typedef unsigned long big64_t ;
#elif ULLONG_MAX == 18446744073709551615ULL
typedef unsigned long long big64_t;
#else
#error "Cannot find unsigned 64bit integer."
#endif

static inline void memxor(uint8_t dst[BLKSIZE], const uint8_t *a, const uint8_t *b)
{
  uint64_t *s = (uint64_t *)(dst);
  const uint64_t *au = (const uint64_t *)(a);
  const uint64_t *bu = (const uint64_t *)(b);

  s[0] = au[0] ^ bu[0];
  s[1] = au[1] ^ bu[1];
}

static inline void memxor3(uint8_t dst[BLKSIZE], const uint8_t *a, 
    const uint8_t *b, const uint8_t *c)
{
  uint64_t *s = (uint64_t *)(dst);
  const uint64_t *au = (const uint64_t *)(a);
  const uint64_t *bu = (const uint64_t *)(b);
  const uint64_t *cu = (const uint64_t *)(c);

  s[0] = au[0] ^ bu[0] ^ cu[0];
  s[1] = au[1] ^ bu[1] ^ cu[1];
}

#ifdef INTERNAL
unsigned long get_current_clock_time_fp(void)
{
  struct timespec ts;
  clock_gettime(CLOCK_MONOTONIC, &ts);
  return ts.tv_sec * 1000000000 + ts.tv_nsec;
}
#endif /* INTERNAL */

etoken_t *fixedkey_perkeyword_token_encryption(dpi_t *dpi, token_t *token)
{
	fstart("dpi: %p, token: %p", dpi, token);
	//assert(dpi != NULL);

  int i, rc, hlen, elen, rs, sklen, count, bsize;
  uint64_t salt;
  uint8_t *skey;
  uint8_t hval[16] = {0, };
  uint8_t eval[16] = {0, };
  uint8_t sbuf[16] = {0, };
  uint8_t tmp[16] = {0, };
  etoken_t *ret;
  entry_t *entry;
  security_context_t *context;
  counter_table_t *table;
  EVP_CIPHER_CTX *ectx;
  const EVP_CIPHER *eevp;
#ifdef INTERNAL
  unsigned long start[10], end[10], tstart, tend;
  int idx = 0;
#endif /* INTERNAL */

#ifdef INTERNAL
  tstart = start[idx] = get_current_clock_time_fp();
#endif /* INTERNAL */
  context = dpi_get_security_context(dpi);
  table = dpi_get_counter_table(dpi);
#ifdef INTERNAL
  end[idx++] = get_current_clock_time_fp();
#endif /* INTERNAL */

#ifdef INTERNAL
  start[idx] = get_current_clock_time_fp();
#endif /* INTERNAL */
  entry = add_counter_table_token(table, token);
#ifdef INTERNAL
  end[idx++] = get_current_clock_time_fp();
#endif /* INTERNAL */

#ifdef INTERNAL
  start[idx] = get_current_clock_time_fp();
#endif /* INTERNAL */
  count = entry->count++;

  ectx = get_context_encryption_context(context);
  //assert(ectx != NULL);
  eevp = get_context_cipher_algorithm(context);
  //assert(eevp != NULL);
  skey = get_context_secret(context, &sklen);
  //assert(skey != NULL);
  salt = get_context_salt(context);
  salt += count;
  VAR_TO_PTR_8BYTES(salt, sbuf);
  rs = get_context_rs_value(context);
  //assert(rs > 0);
  bsize = get_context_block_size(context);
#ifdef INTERNAL
  end[idx++] = get_current_clock_time_fp();
#endif /* INTERNAL */

  dmsg(DPI_DEBUG_MIDDLEBOX, "Token Value to be Encrypted (%d bytes): %s", (token->len), (token->value));

#ifdef INTERNAL
  start[idx] = get_current_clock_time_fp();
#endif /* INTERNAL */
//  for (i=0; i<bsize; i++)
//    tmp[i] = (token->value)[i] ^ skey[i];
    memxor(tmp, (token->value), skey);
#ifdef INTERNAL
  end[idx++] = get_current_clock_time_fp();
#endif /* INTERNAL */

#ifdef INTERNAL
  start[idx] = get_current_clock_time_fp();
#endif /* INTERNAL */
  rc = EVP_EncryptUpdate(ectx, hval, &hlen, tmp, bsize);
#ifdef INTERNAL
  end[idx++] = get_current_clock_time_fp();
#endif /* INTERNAL */
  //assert(rc == 1);

  // tmp -> skey
#ifdef INTERNAL
  start[idx] = get_current_clock_time_fp();
#endif /* INTERNAL */
//  for (i=0; i<bsize; i++) 
  memxor(hval, hval, skey);
  memxor(tmp, hval, sbuf);
  dprint(DPI_DEBUG_MIDDLEBOX, "Secret", skey, 0, bsize, 16);
  dprint(DPI_DEBUG_MIDDLEBOX, "Handle", hval, 0, hlen, 16);
  dprint(DPI_DEBUG_MIDDLEBOX, "Tmp", tmp, 0, bsize, 16);
//    hval[i] = hval[i] ^ skey[i] ^ sbuf[i];
#ifdef INTERNAL
  end[idx++] = get_current_clock_time_fp();
#endif /* INTERNAL */

#ifdef INTERNAL
  start[idx] = get_current_clock_time_fp();
#endif /* INTERNAL */
  rc = EVP_EncryptUpdate(ectx, eval, &elen, tmp, bsize);
#ifdef INTERNAL
  end[idx++] = get_current_clock_time_fp();
#endif /* INTERNAL */
  //assert(rc == 1);

  // tmp -> hval
#ifdef INTERNAL
  start[idx] = get_current_clock_time_fp();
#endif /* INTERNAL */
//  for (i=0; i<bsize; i++)
//    eval[i] = eval[i] ^ hval[i];
  memxor(eval, eval, hval);
#ifdef INTERNAL
  end[idx++] = get_current_clock_time_fp();
#endif /* INTERNAL */

#ifdef INTERNAL
  start[idx] = get_current_clock_time_fp();
#endif /* INTERNAL */
  ret = init_etoken(eval, rs);
  dprint(DPI_DEBUG_MIDDLEBOX, "Encrypted Token", eval, 0, rs, 16);
#ifdef INTERNAL
  tend = end[idx++] = get_current_clock_time_fp();
#endif /* INTERNAL */
  print_interval("others 1", start[0], end[0]);
  print_interval("counter value", start[1], end[1]);
  print_interval("others 2", start[2], end[2]);
  print_interval("xor 1", start[3], end[3]);
  print_interval("aes 1", start[4], end[4]);
  print_interval("xor 2", start[5], end[5]);
  print_interval("aes 2", start[6], end[6]);
  print_interval("xor 4", start[7], end[7]);
  print_interval("others 3", start[8], end[8]);
  print_interval("total", tstart, tend);

//  print_interval("xor 3", start[6], end[6]);
//  print_interval("aes 2", start[7], end[7]);
//  print_interval("xor 4", start[8], end[8]);
//  print_interval("others 3", start[9], end[9]);
//  print_interval("total", tstart, tend);
#ifdef INTERNAL
  printf("\n");
#endif /* INTERNAL */

  //if (!count)
  //  free_token(token);

	ffinish("ret: %p", ret);
	return ret;
}
