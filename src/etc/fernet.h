#ifndef __FERNET_H__
#define __FERNET_H__

#include <stdint.h>

#define FERNET_KEY_BYTES              32
#define FERNET_ENCODED_KEY_BYTES      44
#define FERNET_SIGNING_KEY_BYTES      16
#define FERNET_ENCRYPTION_KEY_BYTES   16
#define FERNET_IV_LENGTH              16
#define FERNET_HMAC_LENGTH            32
#define FERNET_MAX_CLOCK_SKEW         60

typedef struct fernet_st
{
  uint8_t *skey;
  int sklen;
  uint8_t *ekey;
  int eklen;
} fernet_t;

fernet_t *init_fernet(uint8_t *key, int klen);
int fernet_generate_key(uint8_t *key, int *klen);
void free_fernet(fernet_t *fernet);
int fernet_encryption(fernet_t *fernet, uint8_t *in, int ilen, uint8_t *out, int *olen);
int fernet_decryption(fernet_t *fernet, uint8_t *in, int ilen, uint8_t *out, int *olen);

#endif /* __FERNET_H__ */
