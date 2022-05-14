#ifndef __AES_H__
#define __AES_H__

#include <xmmintrin.h>
#include <emmintrin.h>
#include <stdint.h>
#include <wmmintrin.h>
#include <dpi/debug.h>
#include <assert.h>
#include "aes.h"

typedef __m128i block;

typedef struct aes_key_st {
  __m128i key[16];
  int rounds;
} aes_key_t;

#define ROUNDS(ctx) ((ctx)->rounds)

#define EXPAND_ASSIST(v1, v2, v3, v4, shuff_const, aes_const) \
  v2 = _mm_aeskeygenassist_si128(v4, aes_const); \
  v3 = _mm_castps_si128(_mm_shuffle_ps(_mm_castsi128_ps(v3), \
        _mm_castsi128_ps(v1), 16)); \
  v1 = _mm_xor_si128(v1, v3); \
  v3 = _mm_castps_si128(_mm_shuffle_ps(_mm_castsi128_ps(v3), \
        _mm_castsi128_ps(v1), 140)); \
  v1 = _mm_xor_si128(v1, v3); \
  v2 = _mm_shuffle_epi32(v2, shuff_const); \
  v1 = _mm_xor_si128(v1, v2)

extern void aes_128_key_expansion(const uint8_t *userkey, void *key);
extern int aes_128_set_encrypt_key(const uint8_t *userkey, aes_key_t *key);
extern void aes_encrypt(const uint8_t *in, uint8_t *out, const aes_key_t *key);
extern void aes_ecb_encrypt_blks(block *blks, uint8_t nblks, aes_key_t *key);
extern void aes_ecb_encrypt_blks_4(block *blks, aes_key_t *key);
block random_block(void);
#endif /* __AES_H__ */
