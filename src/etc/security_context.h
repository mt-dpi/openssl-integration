#ifndef __SECURITY_CONTEXT_H__
#define __SECURITY_CONTEXT_H__

#include <dpi/dpi_types.h>
#include <openssl/evp.h>

struct security_context_st
{
  uint64_t salt;
  uint8_t *key;
  int klen;
  uint8_t *skey;
  int sklen;
  uint8_t *rgrand;
  int rgrlen;
  const EVP_CIPHER *eevp;
  EVP_CIPHER_CTX *sctx;
  EVP_CIPHER_CTX *ectx;
  int bsize;
  int rs;
};

security_context_t *init_security_context(void);
void free_security_context(security_context_t *context);

void set_context_salt(security_context_t *context, uint64_t salt);
void set_context_encryption_key(security_context_t *context, uint8_t *key, int klen);
void set_context_secret(security_context_t *context, uint8_t *skey, int sklen);
void set_context_rgrand(security_context_t *context, uint8_t *rgrand, int rgrlen);
void set_context_cipher_algorithm(security_context_t *context, const EVP_CIPHER *eevp);
void set_context_rs_value(security_context_t *context, int rs);
void set_context_encryption_context(security_context_t *context);
void set_context_secret_context(security_context_t *context);

uint64_t get_context_salt(security_context_t *context);
uint8_t *get_context_encryption_key(security_context_t *context, int *klen);
uint8_t *get_context_secret(security_context_t *context, int *sklen);
uint8_t *get_context_rgrand(security_context_t *context, int *rgrlen);
const EVP_CIPHER *get_context_cipher_algorithm(security_context_t *context);
int get_context_block_size(security_context_t *context);
int get_context_rs_value(security_context_t *context);
EVP_CIPHER_CTX *get_context_encryption_context(security_context_t *context);
EVP_CIPHER_CTX *get_context_encryption_ctx(security_context_t *context, 
    EVP_CIPHER_CTX **ctx);
EVP_CIPHER_CTX *get_context_secret_context(security_context_t *context);
EVP_CIPHER_CTX *get_context_secret_ctx(security_context_t *context,
    EVP_CIPHER_CTX **ctx);

#endif /* __SECURITY_CONTEXT_H__ */
