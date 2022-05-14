#ifndef __TOKEN_ENCRYPTOR_H__
#define __TOKEN_ENCRYPTOR_H__

#include <dpi/dpi.h>
#include <dpi/dpi_types.h>
#include <dpi/debug.h>
#include "token_encryptor_local.h"

#define NONE_TOKEN_ENCRYPTOR_IDX 0
#define TEST_TOKEN_ENCRYPTOR_IDX 1
#define NONFIXEDKEY_CLUSTER_TOKEN_ENCRYPTOR_IDX 2
#define FIXEDKEY_CLUSTER_TOKEN_ENCRYPTOR_IDX 3
#define FIXEDKEY_PERKEYWORD_TOKEN_ENCRYPTOR_IDX 4
#define FIXEDKEY_GLOBAL_TOKEN_ENCRYPTOR_IDX 5
#define NONFIXEDKEY_PERKEYWORD_TOKEN_ENCRYPTOR_IDX 6
#define NONFIXEDKEY_GLOBAL_TOKEN_ENCRYPTOR_IDX 7

token_encryptor_t *init_token_encryptor(conf_t *conf);
void free_token_encryptor(token_encryptor_t *module);
etoken_t *test_token_encryption(dpi_t *dpi, token_t *token);
etoken_t *nonfixedkey_cluster_token_encryption(dpi_t *dpi, token_t *token);
etoken_t *fixedkey_cluster_token_encryption(dpi_t *dpi, token_t *token);
etoken_t *fixedkey_perkeyword_token_encryption(dpi_t *dpi, token_t *token);
etoken_t *fixedkey_global_token_encryption(dpi_t *dpi, token_t *token);
etoken_t *nonfixedkey_perkeyword_token_encryption(dpi_t *dpi, token_t *token);
etoken_t *nonfixedkey_global_token_encryption(dpi_t *dpi, token_t *token);

#endif /* __TOKEN_ENCRYPTOR_H__ */
