#include "oblivious_transfer.h"

#include <string.h>
#include <unistd.h>

#include <dpi/debug.h>
#include <dpi/defines.h>
#include <openssl/bio.h>
#include <openssl/rand.h>
#include <openssl/evp.h>

ot_t *init_ot(int nbits, SSL *ssl, BIGNUM *prime, BIGNUM *generator)
{
  fstart("ssl: %p", ssl);

  ot_t *ret;
  ret = (ot_t *)calloc(1, sizeof(ot_t));
  ret->group = init_prime_group(nbits, prime, generator);
  ret->group->nbits = nbits;
  ret->ssl = ssl;

  ffinish("ret: %p", ret);
  return ret;
}

void free_ot(ot_t *ot)
{
  fstart("ot: %p", ot);

  if (ot)
  {
    free(ot);
  }

  ffinish();
}

uint8_t *ot_hash(ot_t *ot, BIGNUM *m, int mlen)
{
  fstart("ot: %p, m: %p, mlen: %d", ot, m, mlen);
  assert(m != NULL);

  int rc, blen, hlen, tlen;
  uint8_t *ret;
  uint8_t buf[BUF_SIZE] = {0, };
  EVP_MD_CTX *ctx;

  ret = NULL;
  ctx = EVP_MD_CTX_new();
  if (!ctx) goto out;

  rc = EVP_DigestInit_ex(ctx, EVP_shake256(), NULL);
  if (!rc) 
  {
    emsg("EVP_DigestInit_ex error");
    goto out;
  }

  blen = BN_bn2bin(m, buf);
  rc = EVP_DigestUpdate(ctx, buf, blen);
  if (!rc)
  {
    emsg("EVP_DigestUpdate() error");
    goto out;
  }

  ret = (uint8_t *)calloc(mlen, sizeof(uint8_t));
  rc = EVP_DigestFinal_ex(ctx, buf, &hlen);
  if (!rc)
  {
    emsg("EVP_DigestFinal_ex() error");
    goto out;
  }
  EVP_MD_CTX_free(ctx);
  ctx = NULL;
  
  tlen = 0;
  while (tlen < mlen)
  {
    ctx = EVP_MD_CTX_new();
    rc = EVP_DigestInit_ex(ctx, EVP_shake256(), NULL);
    rc = EVP_DigestUpdate(ctx, buf, hlen);
    rc = EVP_DigestFinal_ex(ctx, buf, &hlen);
    if ((mlen - tlen) < hlen)
    {
      memcpy(ret + tlen, buf, (mlen - tlen));
      tlen += (mlen - tlen);
    }
    else
    {
      memcpy(ret + tlen, buf, hlen);
      tlen += hlen;
    }
  } 
  dprint(DPI_DEBUG_CIRCUIT, "Hash", ret, 0, mlen, 16);

out:
  if (ctx)
    EVP_MD_CTX_free(ctx);
  ffinish("ret: %p", ret);
  return ret;
}

pg_t *init_prime_group(int nbits, BIGNUM *prime, BIGNUM *generator)
{
  fstart("nbits: %d", nbits);
  assert(nbits > 0);

  pg_t *ret;
  BIO *bio;
  const BIGNUM *one;
  BIGNUM *two;

  bio = BIO_new_fp(stdout, BIO_NOCLOSE);
  one = BN_value_one();
  two = BN_new();
  BN_add(two, one, one);

  ret = (pg_t *)calloc(1, sizeof(pg_t));
  ret->nbits = nbits;
  ret->ctx = BN_CTX_new();
  if (!prime)
    ret->prime = pg_generate_prime(ret, nbits);
  else
    ret->prime = prime;
  ret->prime_m1 = BN_new();
  ret->prime_m2 = BN_new();
  BN_sub(ret->prime_m1, (const BIGNUM *)ret->prime, one);
  BN_sub(ret->prime_m2, (const BIGNUM *)ret->prime, two);
  if (!generator)
    ret->generator = pg_find_generator(ret);
  else
    ret->generator = generator;

#ifdef CIRCUIT_DEBUG
  printf("prime: ");
  BN_print(bio, ret->prime);
  printf("\n");
  printf("prime_m1: ");
  BN_print(bio, ret->prime_m1);
  printf("\n");
  printf("prime_m2: ");
  BN_print(bio, ret->prime_m2);
  printf("\n");
  printf("generator: ");
  BN_print(bio, ret->generator);
  printf("\n");
#endif /* CIRCUIT_DEBUG */

  BN_free(two);
  BIO_free(bio);

  ffinish("ret: %p", ret);
  return ret;
}

void free_prime_group(pg_t *group)
{
  fstart("group: %p", group);

  if (group)
  {
    free(group);
  }

  ffinish();
}

int send_ot_params(int sock, ot_t *ot)
{
  fstart("sock: %d, ot: %p", sock, ot);
  assert(ot != NULL);

  int ret, sent, rcvd;
  uint8_t buf[BUF_SIZE] = {0, };
  uint8_t *p;
  uint16_t len;

  ret = FAILURE;
  p = buf;
  
  // nbits (4 bytes) || length of the prime number (2 bytes) || prime 
  // || length of the generator (2 bytes) || generator
  VAR_TO_PTR_4BYTES(ot->group->nbits, p);
  len = BN_num_bytes(ot->group->prime);
  VAR_TO_PTR_2BYTES(len, p);
  BN_bn2bin(ot->group->prime, p);
  p += len;

  len = BN_num_bytes(ot->group->generator);
  VAR_TO_PTR_2BYTES(len, p);
  BN_bn2bin(ot->group->generator, p);
  p += len;

  // garbler -> evaluator: (p, g)
  sent = write(sock, buf, (p-buf));
  assert(sent == (p-buf));
  memset(buf, 0, BUF_SIZE);

  // evaluator -> garbler : ack
  rcvd = read(sock, buf, 1);
  p = buf;
  assert(rcvd == 1);
  assert(*p == 1);
  dmsg(DPI_DEBUG_CIRCUIT, "[garbler] ACK received from the evaluator");

  ret = SUCCESS;
  ffinish("ret: %d", ret);
  return ret;
}

ot_t *receive_ot_params(int sock)
{
  fstart("sock: %d", sock);

  ot_t *ret;
  int nbits, sent, rcvd;
  uint8_t buf[BUF_SIZE] = {0, };
  uint8_t *p;
  uint16_t len;
  BIGNUM *prime, *generator;
  BIO *bio;

  bio = BIO_new_fp(stdout, BIO_NOCLOSE);
  p = buf;

  rcvd = read(sock, p, 4);
  assert(rcvd == 4);
  PTR_TO_VAR_4BYTES(p, nbits);

  rcvd = read(sock, p, 2);
  assert(rcvd == 2);
  PTR_TO_VAR_2BYTES(p, len);

  rcvd = read(sock, p, len);
  assert(rcvd == len);
  prime = BN_bin2bn(p, len, NULL);
  p += len;

  rcvd = read(sock, p, 2);
  assert(rcvd == 2);
  PTR_TO_VAR_2BYTES(p, len);

  rcvd = read(sock, p, len);
  assert(rcvd == len);
  generator = BN_bin2bn(p, len, NULL);
  p += len;

#ifdef CIRCUIT_DEBUG
  printf("prime: ");
  BN_print(bio, prime);
  printf("\n");

  printf("generator: ");
  BN_print(bio, generator);
  printf("\n");
#endif /* CIRCUIT_DEBUG */

  ret = init_ot(nbits, NULL, prime, generator);

  p = buf;
  *p = 1;
  sent = write(sock, buf, 1);
  assert(sent == 1);
  dmsg(DPI_DEBUG_CIRCUIT, "[evaluator] ACK sent to the garbler");

  ffinish("ret: %p", ret);
  return ret;
}

int send_ot_message(int sock, ot_t *ot, uint8_t *msg0, int mlen0, uint8_t *msg1, int mlen1)
{
  fstart("sock: %d, ot: %p, msg0: %p, mlen0: %d, msg1: %p, mlen1: %d", sock, ot, msg0, mlen0, msg1, mlen1);
  assert(ot != NULL);
  assert(msg0 != NULL);
  assert(msg1 != NULL);

  int ret, sent, rcvd;
  BIO *bio;
  BIGNUM *c, *h0, *h1, *k, *c1, *tmp;
  uint8_t buf[BUF_SIZE] = {0, };
  uint8_t *p, *e0, *e1, *hash;
  uint16_t len;

  ret = FAILURE;
  bio = BIO_new_fp(stdout, BIO_NOCLOSE);
  p = buf;

  tmp = pg_random_int(ot->group);
  c = pg_gen_pow(ot->group, tmp);
  len = BN_num_bytes(c);
  VAR_TO_PTR_2BYTES(len, p);
  BN_bn2bin(c, p);
  p += len;
  BN_free(tmp);

  // garbler -> evaluator: c
  sent = write(sock, buf, (p-buf));
  assert(sent == (p-buf));
  memset(buf, 0, BUF_SIZE);

  // evaluator -> garbler: hb
  p = buf;
  rcvd = read(sock, p, 2);
  assert(rcvd == 2);
  PTR_TO_VAR_2BYTES(p, len);

  rcvd = read(sock, p, len);
  assert(rcvd == len);
  h0 = BN_bin2bn(p, len, NULL);

  tmp = pg_inv(ot->group, h0);
  h1 = pg_mul(ot->group, c, tmp);
  k = pg_random_int(ot->group);
  c1 = pg_gen_pow(ot->group, k);
  BN_free(tmp);

#ifdef CIRCUIT_DEBUG
  printf("c: ");
  BN_print(bio, c);
  printf("\n");

  printf("h0: ");
  BN_print(bio, h0);
  printf("\n");

  printf("h1: ");
  BN_print(bio, h1);
  printf("\n");

  printf("k: ");
  BN_print(bio, k);
  printf("\n");

  printf("c1: ");
  BN_print(bio, c1);
  printf("\n");
#endif /* CIRCUIT_DEBUG */

  tmp = pg_pow(ot->group, h0, k);
#ifdef CIRCUIT_DEBUG
  printf("to be hashed 0 (%d bytes): ", mlen0);
  BN_print(bio, tmp);
  printf("\n");
#endif /* CIRCUIT_DEBUG */
  hash = ot_hash(ot, tmp, mlen0);
  e0 = pg_xor_two_bytes(msg0, hash, mlen0);
  BN_free(tmp);
  free(hash);

  tmp = pg_pow(ot->group, h1, k);
#ifdef CIRCUIT_DEBUG
  printf("to be hashed 1 (%d bytes): ", mlen1);
  BN_print(bio, tmp);
  printf("\n");
#endif /* CIRCUIT_DEBUG */
  hash = ot_hash(ot, tmp, mlen1);
  e1 = pg_xor_two_bytes(msg1, hash, mlen1);
  free(hash);

  // garbler -> evaluator: 
  // len(c1) (2 bytes) || c1 || len(e0) (2 bytes) || e0 || len(e1) (2 bytes) || e1

  p = buf;
  len = BN_num_bytes(c1);
  VAR_TO_PTR_2BYTES(len, p);
  BN_bn2bin(c1, p);
  p += len;

  VAR_TO_PTR_2BYTES(mlen0, p);
  memcpy(p, e0, mlen0);
  p += mlen0;

  VAR_TO_PTR_2BYTES(mlen1, p);
  memcpy(p, e1, mlen1);
  p += mlen1;

  sent = write(sock, buf, (p-buf));
  assert(sent == (p-buf));
  memset(buf, 0, BUF_SIZE);

  dprint(DPI_DEBUG_CIRCUIT, "e0", e0, 0, mlen0, 16);
  dprint(DPI_DEBUG_CIRCUIT, "e1", e1, 0, mlen1, 16);

  BIO_free(bio);
  BN_free(c);
  BN_free(h0);
  BN_free(h1);
  BN_free(c1);
  free(e0);
  free(e1);

  ret = SUCCESS;
  ffinish("ret: %d", ret);
  return ret;
}

int receive_ot_message(int sock, ot_t *ot, int b, uint8_t *out, int *olen)
{
  fstart("sock: %d, ot: %p", sock, ot);
  assert(ot != NULL);

  int ret, sent, rcvd, elen, elen0, elen1;
  uint8_t buf[BUF_SIZE] = {0, };
  uint8_t *p, *e, *e0, *e1, *hash, *t;
  uint16_t len;
  BIO *bio;
  BIGNUM *c, *x, *x_pow, *tbs, *tmp, *c1;

  ret = FAILURE;
  bio = BIO_new_fp(stdout, BIO_NOCLOSE);

  p = buf;
  rcvd = read(sock, p, 2);
  assert(rcvd == 2);
  PTR_TO_VAR_2BYTES(p, len);

  rcvd = read(sock, p, len);
  assert(rcvd == len);
  c = BN_bin2bn(p, len, NULL);

  x = pg_random_int(ot->group);
  x_pow = pg_gen_pow(ot->group, x);
  
  if (b == 0)
  {
    tbs = x_pow;
  }
  else
  {
    tmp = pg_inv(ot->group, x_pow);
    tbs = pg_mul(ot->group, c, tmp);
    BN_free(tmp);
  }

  p = buf;
  len = BN_num_bytes(tbs);
  VAR_TO_PTR_2BYTES(len, p);
  BN_bn2bin(tbs, p);
  p += len;

  // evaluator -> garbler: length (2 bytes) || hb
  sent = write(sock, buf, (p-buf));
  assert(sent == (p-buf));

  // garbler -> evaluator: 
  // len(c1) (2 bytes) || c1 || len(e0) (2 bytes) || e0 || len(e1) (2 bytes) || e1
  rcvd = read(sock, buf, 2);
  assert(rcvd == 2);
  p = buf;
  PTR_TO_VAR_2BYTES(p, len);

  rcvd = read(sock, p, len);
  assert(rcvd == len);
  c1 = BN_bin2bn(p, len, NULL);

  rcvd =read(sock, p, 2);
  assert(rcvd == 2);
  PTR_TO_VAR_2BYTES(p, elen0);

  rcvd = read(sock, p, elen0);
  assert(rcvd == elen0);
  e0 = (uint8_t *)calloc(elen0, sizeof(uint8_t));
  memcpy(e0, p, elen0);
  p += elen0;

  rcvd = read(sock, p, 2);
  assert(rcvd == 2);
  PTR_TO_VAR_2BYTES(p, elen1);

  rcvd = read(sock, p, elen1);
  assert(rcvd == elen1);
  e1 = (uint8_t *)calloc(elen1, sizeof(uint8_t));
  memcpy(e1, p, elen1);
  p += elen1;

#ifdef CIRCUIT_DEBUG
  printf("c: ");
  BN_print(bio, c);
  printf("\n");

  if (b == 0)
    printf("h0: ");
  else
    printf("h1: ");
  BN_print(bio, tbs);
  printf("\n");

  printf("c1: ");
  BN_print(bio, c1);
  printf("\n");
#endif /* CIRCUIT_DEBUG */

  e = b == 0? e0 : e1;
  elen = b == 0? elen0 : elen1;

  tmp = pg_pow(ot->group, c1, x);
#ifdef CIRCUIT_DEBUG
  printf("To be hashed (%d bytes): ", elen);
  BN_print(bio, tmp);
  printf("\n");
#endif /* CIRCUIT_DEBUG */

  hash = ot_hash(ot, tmp, elen);
  t = pg_xor_two_bytes(e, hash, elen);
  *olen = elen;
  memcpy(out, t, *olen);
  BN_free(tmp);

  dprint(DPI_DEBUG_CIRCUIT, "Received Message", out, 0, (*olen), 16);

  dprint(DPI_DEBUG_CIRCUIT, "e0", e0, 0, elen0, 16);
  dprint(DPI_DEBUG_CIRCUIT, "e1", e1, 0, elen1, 16);


  BN_free(c);
  BN_free(c1);
  BN_free(tbs);
  free(e0);
  free(e1);
  free(hash);
  free(t);

  ret = SUCCESS;
  ffinish("ret: %d", ret);
  return ret;
}

BIGNUM *pg_generate_prime(pg_t *group, int nbits)
{
  fstart("pg: %p, nbits: %d", group, nbits);
  assert(group != NULL);
  
  int rc;
  const char *seed = "random seed";
  BIGNUM *ret;

  ret = BN_new();
  RAND_seed(seed, sizeof(seed));
  rc = BN_generate_prime_ex(ret, nbits, 0, NULL, NULL, NULL);
  if (!rc)
  {
    emsg("generate prime error");
    BN_free(ret);
    ret = NULL;
    goto out;
  }

out:
  ffinish("ret: %p", ret);
  return ret;
}

uint8_t *pg_xor_two_bytes(uint8_t *s1, uint8_t *s2, int len)
{
  fstart("s1: %p, s2: %p, len: %d", s1, s2, len);
  assert(s1 != NULL);
  assert(s2 != NULL);

  int i;
  uint8_t *ret;

  ret = (uint8_t *)calloc(len, sizeof(uint8_t));
  for (i=0; i<len; i++)
  {
    ret[i] = s1[i] ^ s2[i];
  }

  ffinish();
  return ret;
}

BIGNUM *pg_find_generator(pg_t *group)
{
  fstart("group: %p", group);
  assert(group != NULL);

  int rc;
  BN_CTX *ctx;
  BIGNUM *ret, *tmp1, *tmp2;
  ctx = BN_CTX_new();
  tmp1 = BN_new();
  tmp2 = BN_new();

  while (1)
  {
    rc = BN_rand(tmp1, group->nbits, BN_RAND_TOP_ANY, BN_RAND_BOTTOM_ANY);
    if (!rc) 
    {
      emsg("Error in generating the random BIGNUM");
      ret = NULL;
      goto err;
    }
    if (BN_is_one(tmp1) || !BN_is_odd(tmp1))
      continue;

    rc = BN_mod_exp(tmp2, tmp1, group->prime_m1, group->prime, ctx);
    if (!rc)
    {
      emsg("Error in calculating the exponentiation");
      ret = NULL;
      goto err;
    }

    if (BN_is_one(tmp2))
    {
      ret = tmp1;
      imsg(DPI_DEBUG_CIRCUIT, "Find the generator");
      goto out;
    }
  }

err:
  BN_free(tmp1);
out:
  BN_free(tmp2);
  BN_CTX_free(ctx);
  ffinish("ret: %p", ret);
  return ret;
}

BIGNUM *pg_mul(pg_t *group, BIGNUM *num1, BIGNUM *num2)
{
  fstart("group: %p", group);
  assert(group != NULL);
  assert(num1 != NULL);
  assert(num2 != NULL);

  BN_CTX *ctx;
  BIGNUM *ret;
  int rc;

  ctx = BN_CTX_new();
  ret = BN_new();
  rc = BN_mod_mul(ret, num1, num2, group->prime, ctx);

  BN_CTX_free(ctx);
  ffinish("ret: %p", ret);
  return ret;
}

BIGNUM *pg_pow(pg_t *group, BIGNUM *base, BIGNUM *exponent)
{
  fstart("group: %p", group);
  assert(group != NULL);
  assert(base != NULL);
  assert(exponent != NULL);

  int rc;
  BN_CTX *ctx;
  BIGNUM *ret;
  ctx = BN_CTX_new();
  ret = BN_new();

  rc = BN_mod_exp(ret, base, exponent, group->prime, ctx);
  if (!rc)
  {
    emsg("Calculating the bignum exponentiation failure");
  }

  BN_CTX_free(ctx);
  ffinish("ret: %p", ret);
  return ret;
}

BIGNUM *pg_gen_pow(pg_t *group, BIGNUM *exponent)
{
  fstart("group: %p", group);
  assert(group != NULL);
  assert(exponent != NULL);

  BIGNUM *ret;

  ret = pg_pow(group, group->generator, exponent);

  ffinish("ret: %p", ret);
  return ret;
}

BIGNUM *pg_inv(pg_t *group, BIGNUM *num)
{
  fstart("group: %p", group);
  assert(group != NULL);
  assert(num != NULL);

  BN_CTX *ctx;
  BIGNUM *ret;

  ctx = BN_CTX_new();
  ret = BN_mod_inverse(NULL, num, group->prime, ctx);

  BN_CTX_free(ctx);
  ffinish("ret: %p", ret);
  return ret;
}

BIGNUM *pg_random_int(pg_t *group)
{
  fstart("group: %p", group);
  assert(group != NULL);

  int rc;
  BIO *bio;
  BN_CTX *ctx;
  BIGNUM *ret;
  bio = BIO_new_fp(stdout, BIO_NOCLOSE);
  ctx = BN_CTX_new();
  ret = BN_new();

  rc = BN_rand_range(ret, group->prime_m2);
  if (!rc)
  {
    emsg("Error in generating the random integer");
  }

  rc = BN_mod_add(ret, ret, BN_value_one(), group->prime, ctx);
  if (!rc)
  {
    emsg("Error in generating the random integer");
  }
#ifdef CIRCUIT_DEBUG
  printf("random: ");
  BN_print(bio, ret);
  printf("\n");
#endif /* CIRCUIT_DEBUG */
  BIO_free(bio);
  BN_CTX_free(ctx);

  ffinish("ret: %p", ret);
  return ret;
}
