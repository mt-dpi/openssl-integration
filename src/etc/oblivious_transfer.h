#ifndef __OBLIVIOUS_TRANSFER_H__
#define __OBLIVIOUS_TRANSFER_H__

#include <stdint.h>
#include <openssl/bn.h>

typedef struct prime_group_st
{
  int nbits;
  BIGNUM *prime;
  BIGNUM *prime_m1;
  BIGNUM *prime_m2;
  BIGNUM *generator;
  BIGNUM *c;
  BN_CTX *ctx;
  int plen;

} pg_t;

typedef struct ot_st
{
  pg_t *group;
  int sock;
  SSL *ssl;
} ot_t;

ot_t *init_ot(int nbits, SSL *ssl, BIGNUM *prime, BIGNUM *generator);
void free_ot(ot_t *ot);

pg_t *init_prime_group(int nbits, BIGNUM *prime, BIGNUM *generator);
void free_prime_group(pg_t *group);

int send_ot_params(int sock, ot_t *ot);
ot_t *receive_ot_params(int sock);
int send_ot_message(int sock, ot_t *ot, uint8_t *msg0, int mlen0, 
    uint8_t *msg1, int mlen1);
int receive_ot_message(int sock, ot_t *ot, int b, uint8_t *out, int *olen);

int pg_get_next_prime(int num);
BIGNUM *pg_generate_prime(pg_t *group, int nbits);
uint8_t *pg_xor_two_bytes(uint8_t *s1, uint8_t *s2, int len);
BIGNUM *pg_find_generator(pg_t *group);
BIGNUM *pg_mul(pg_t *group, BIGNUM *num1, BIGNUM *num2);
BIGNUM *pg_pow(pg_t *group, BIGNUM *base, BIGNUM *exponent);
BIGNUM *pg_gen_pow(pg_t *group, BIGNUM *exponent);
BIGNUM *pg_inv(pg_t *group, BIGNUM *num);
BIGNUM *pg_random_int(pg_t *group);

int ot_get_result(ot_t *ot, uint8_t *ain, int ailen, uint8_t *bkey, int bklen);
uint8_t *ot_hash(ot_t *ot, BIGNUM *m, int mlen);

#endif /* __OBLIVIOUS_TRANSFER_H__ */
