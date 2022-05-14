#ifndef __TOKEN_ENCRYPTOR_LOCAL_H__
#define __TOKEN_ENCRYPTOR_LOCAL_H__

#include "../etc/token.h"
#include "token_encryptor.h"

typedef struct token_encryptor_st
{
  etoken_t *(*token_encryption)(dpi_t *dpi, token_t *token);
} token_encryptor_t;

#endif /* __TOKEN_ENCRYPTOR_LOCAL_H__ */
