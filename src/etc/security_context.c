#include "security_context.h"
#include <dpi/debug.h>
#include <stdlib.h>
#include <string.h>

security_context_t *init_security_context(void)
{
  fstart();

  security_context_t *ret;
  ret = (security_context_t *)calloc(1, sizeof(security_context_t));

  ffinish("ret: %p", ret);
  return ret;
}

void free_security_context(security_context_t *context)
{
  fstart("context: %p", context);

  if (context)
  {
    if (context->key)
      free(context->key);

    if (context->rgrand)
      free(context->rgrand);

    free(context);
  }

  ffinish();
}

void set_context_salt(security_context_t *context, uint64_t salt)
{
  fstart("context: %p, salt: %lu", context, salt);

  context->salt = salt;

  ffinish();
}

void set_context_encryption_key(security_context_t *context, uint8_t *key, int klen)
{
  fstart("context: %p, key: %p, klen: %d", context, key, klen);

  context->key = (uint8_t *)calloc(klen, sizeof(uint8_t));
  memcpy(context->key, key, klen);
  context->klen = klen;

  ffinish();
}

void set_context_secret(security_context_t *context, uint8_t *skey, int sklen)
{
  fstart("context: %p, skey: %p, sklen: %d", context, skey, sklen);

  context->skey = (uint8_t *)calloc(1, sklen);
  memcpy(context->skey, skey, sklen);
  context->sklen = sklen;

  ffinish();
}

void set_context_rgrand(security_context_t *context, uint8_t *rgrand, int rgrlen)
{
  fstart("context: %p, rgrand: %p, rgrlen: %d", context, rgrand, rgrlen);

  context->rgrand = (uint8_t *)malloc(rgrlen);
  memcpy(context->rgrand, rgrand, rgrlen);
  context->rgrlen = rgrlen;

  ffinish();
}

void set_context_cipher_algorithm(security_context_t *context, const EVP_CIPHER *eevp)
{
  fstart("context: %p, eevp: %p", context, eevp);

  context->eevp = eevp;
  context->bsize = EVP_CIPHER_block_size(eevp);

  ffinish();
}

void set_context_rs_value(security_context_t *context, int rs)
{
  fstart("context: %p, rs: %d", context, rs);

  context->rs = rs;

  ffinish();
}

void set_context_encryption_context(security_context_t *context)
{
  fstart("context: %p", context);

  EVP_CIPHER_CTX *ectx;
  ectx = EVP_CIPHER_CTX_new();
  context->ectx = ectx;
  EVP_EncryptInit_ex(context->ectx, context->eevp, NULL, context->key, NULL);

  ffinish();
}

void set_context_secret_context(security_context_t *context)
{
  fstart("context: %p", context);

  EVP_CIPHER_CTX *sctx;
  sctx = EVP_CIPHER_CTX_new();
  context->sctx = sctx;
  EVP_EncryptInit_ex(context->sctx, context->eevp, NULL, context->skey, NULL);

  ffinish();
}

uint64_t get_context_salt(security_context_t *context)
{
  fstart("context: %p", context);

  uint64_t ret;
  ret = context->salt;

  ffinish("ret: %lu", ret);
  return ret;
}

uint8_t *get_context_encryption_key(security_context_t *context, int *klen)
{
  fstart("context: %p, klen: %p", context, klen);

  uint8_t *ret;
  ret = context->key;
  *klen = context->klen;

  ffinish("ret: %p", ret);
  return ret;
}

uint8_t *get_context_secret(security_context_t *context, int *sklen)
{
  fstart("context: %p, sklen: %p", context, sklen);
  
  uint8_t *ret;
  ret = context->skey;
  *sklen = context->sklen;

  ffinish("ret: %p", ret);
  return ret;
}

uint8_t *get_context_rgrand(security_context_t *context, int *rgrlen)
{
  fstart("context: %p, rgrlen: %p", context, rgrlen);

  uint8_t *ret;
  ret = context->rgrand;
  *rgrlen = context->rgrlen;

  ffinish("ret: %p", ret);
  return ret;
}

const EVP_CIPHER *get_context_cipher_algorithm(security_context_t *context)
{
  fstart("context: %p", context);

  const EVP_CIPHER *ret;
  ret = context->eevp;

  ffinish("ret: %p", ret);
  return ret;
}

int get_context_block_size(security_context_t *context)
{
  fstart("context: %p", context);
  assert(context != NULL);

  int ret;
  ret = context->bsize;

  ffinish("ret: %d", ret);
  return ret;
}

int get_context_rs_value(security_context_t *context)
{
  fstart("context: %p", context);

  int ret;
  ret = context->rs;

  ffinish("ret: %d", ret);
  return ret;
}

EVP_CIPHER_CTX *get_context_encryption_context(security_context_t *context)
{
  fstart("context: %p", context);

  EVP_CIPHER_CTX *ret;
  ret = context->ectx;

  ffinish("ret: %p", ret);
  return ret;
}

EVP_CIPHER_CTX *get_context_encryption_ctx(security_context_t *context,
    EVP_CIPHER_CTX **ctx)
{
  fstart("context: %p", context);

  EVP_CIPHER_CTX *ret;
  (*ctx) = context->ectx;
  ret = context->ectx;

  ffinish("ret: %p", ret);
  return ret;
}


EVP_CIPHER_CTX *get_context_secret_context(security_context_t *context)
{
  fstart("context: %p", context);

  EVP_CIPHER_CTX *ret;
  ret = context->sctx;

  ffinish("ret: %p", ret);
  return ret;
}

EVP_CIPHER_CTX *get_context_secret_ctx(security_context_t *context,
    EVP_CIPHER_CTX **ctx)
{
  fstart("context: %p", context);

  EVP_CIPHER_CTX *ret;
  (*ctx) = context->sctx;
  ret = context->sctx;

  ffinish("ret: %p", ret);
  return ret;
}
