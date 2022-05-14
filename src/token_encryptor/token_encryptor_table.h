#ifndef __TOKEN_ENCRYPTOR_TABLE_H__
#define __TOKEN_ENCRYPTOR_TABLE_H__

#include "token_encryptor.h"

static etoken_t *(*token_encryption_table[8])(dpi_t *dpi, token_t *token) = {
	NULL,
	test_token_encryption,
	nonfixedkey_cluster_token_encryption,
	fixedkey_cluster_token_encryption,
	fixedkey_perkeyword_token_encryption,
	fixedkey_global_token_encryption,
	nonfixedkey_perkeyword_token_encryption,
	nonfixedkey_global_token_encryption,
};
#endif /* __TOKEN_ENCRYPTOR_TABLE_H__ */
