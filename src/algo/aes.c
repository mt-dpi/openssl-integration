#include <wmmintrin.h>
#include <dpi/debug.h>
#include <stdint.h>
#include <assert.h>
#include "aes.h"

static __m128i cur_seed;

inline void aes_128_key_expansion(const uint8_t *userkey, void *key)
{
  fstart("userkey: %p, key: %p", userkey, key);
  assert(userkey != NULL);
  assert(key != NULL);

  __m128i x0, x1, x2;
  __m128i *kp = (__m128i *)key;
  kp[0] = x0 = _mm_loadu_si128((__m128i *)userkey);
  x2 = _mm_setzero_si128();
  EXPAND_ASSIST(x0, x1, x2, x0, 255, 1);
  kp[1] = x0;
  EXPAND_ASSIST(x0, x1, x2, x0, 255, 2);
  kp[2] = x0;
  EXPAND_ASSIST(x0, x1, x2, x0, 255, 4);
  kp[3] = x0;
  EXPAND_ASSIST(x0, x1, x2, x0, 255, 8);
  kp[4] = x0;
  EXPAND_ASSIST(x0, x1, x2, x0, 255, 16);
  kp[5] = x0;
  EXPAND_ASSIST(x0, x1, x2, x0, 255, 32);
  kp[6] = x0;
  EXPAND_ASSIST(x0, x1, x2, x0, 255, 64);
  kp[7] = x0;
  EXPAND_ASSIST(x0, x1, x2, x0, 255, 128);
  kp[8] = x0;
  EXPAND_ASSIST(x0, x1, x2, x0, 255, 27);
  kp[9] = x0;
  EXPAND_ASSIST(x0, x1, x2, x0, 255, 54);
  kp[10] = x0;

  ffinish();
}

inline int aes_128_set_encrypt_key(const uint8_t *userkey, aes_key_t *key)
{
  fstart("userkey: %p, key: %p", userkey, key);
  assert(userkey != NULL);
  assert(key != NULL);

  aes_128_key_expansion(userkey, key);

  ffinish();
  return 0;
}

inline void aes_encrypt(const uint8_t *in, uint8_t *out, const aes_key_t *key)
{
  fstart("in: %p, out: %p, key: %p", in, out, key);
  assert(in != NULL);
  assert(out != NULL);
  assert(key != NULL);

  int i, rnds;
  const __m128i *sched;
  __m128i tmp;

  rnds = ROUNDS(key);
  sched = ((__m128i *)(key->key));
  tmp = _mm_load_si128((__m128 *) in); 
  tmp = _mm_xor_si128(tmp, sched[0]);

  for (i=1; i<rnds; i++)
    tmp = _mm_aesenc_si128(tmp, sched[i]);
  tmp = _mm_aesenclast_si128(tmp, sched[i]);
  _mm_store_si128((__m128i *)out, tmp);

  ffinish();
}

inline void aes_ecb_encrypt_blks(block *blks, uint8_t nblks, aes_key_t *key)
{
  fstart("blks: %p, nblks: %u, key: %p", blks, nblks, key);
  assert(blks != NULL);
  assert(nblks > 0);
  assert(key != NULL);

  uint8_t i, j, rnds;
  const __m128i *sched;

  rnds = ROUNDS(key);
  sched = ((__m128i *)(key->key));
  for (i=0; i<nblks; ++i)
    blks[i] = _mm_xor_si128(blks[i], sched[0]);

  for (i=1; i<rnds; ++i)
    for (j=0; j<nblks; ++j)
      blks[j] = _mm_aesenc_si128(blks[j], sched[i]);

  for (j=0; j<nblks; ++j)
    blks[j] = _mm_aesenclast_si128(blks[j], sched[i]);

  ffinish();
}

inline void aes_ecb_encrypt_blks_4(block *blks, aes_key_t *key)
{
  fstart("blks: %p, key: %p", blks, key);
  assert(blks != NULL);
  assert(key != NULL);

  uint8_t i, rnds;
  const __m128i *sched;

  rnds = ROUNDS(key);
  sched = ((__m128i *)(key->key));

  blks[0] = _mm_xor_si128(blks[0], sched[0]);
  blks[1] = _mm_xor_si128(blks[1], sched[0]);
  blks[2] = _mm_xor_si128(blks[2], sched[0]);
  blks[3] = _mm_xor_si128(blks[3], sched[0]);

  for (i=1; i<rnds; ++i)
  {
    blks[0] = _mm_aesenc_si128(blks[0], sched[i]);
    blks[1] = _mm_aesenc_si128(blks[1], sched[i]);
    blks[2] = _mm_aesenc_si128(blks[2], sched[i]);
    blks[3] = _mm_aesenc_si128(blks[3], sched[i]);
  }

  blks[0] = _mm_aesenclast_si128(blks[0], sched[i]);
  blks[1] = _mm_aesenclast_si128(blks[1], sched[i]);
  blks[2] = _mm_aesenclast_si128(blks[2], sched[i]);
  blks[3] = _mm_aesenclast_si128(blks[3], sched[i]);

  ffinish();
}

block random_block(void)
{
  fstart();

  block cur_seed_split;
  block multiplier;
  block adder;
  block mod_mask;
  block sra_mask;

  static const uint32_t mult[4] = {214013, 17405, 214013, 69069};
  static const uint32_t gadd[4] = {2531011, 10395331, 13737667, 1};
  static const uint32_t mask[4] = {0xffffffff, 0, 0xffffffff, 0};
  static const uint32_t masklo[4] = {0x00007fff, 0x00007fff, 0x00007fff, 0x00007fff};

  adder = _mm_load_si128((block *)gadd);
  multiplier = _mm_load_si128((block *)mult);
  mod_mask = _mm_load_si128((block *)mask);
  sra_mask = _mm_load_si128((block *)masklo);
  cur_seed_split = _mm_shuffle_epi32(cur_seed, _MM_SHUFFLE(2, 3, 0, 1));
  cur_seed = _mm_mul_epu32(cur_seed, multiplier);
  multiplier = _mm_shuffle_epi32(multiplier, _MM_SHUFFLE(2, 3, 0, 1));
  cur_seed_split = _mm_mul_epu32(cur_seed_split, multiplier);
  cur_seed = _mm_and_si128(cur_seed, mod_mask);
  cur_seed_split = _mm_and_si128(cur_seed_split, mod_mask);
  cur_seed_split = _mm_shuffle_epi32(cur_seed_split, _MM_SHUFFLE(2, 3, 0, 1));
  cur_seed = _mm_or_si128(cur_seed, cur_seed_split);
  cur_seed = _mm_add_epi32(cur_seed, adder);

  ffinish();
  return cur_seed;
}
