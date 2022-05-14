#ifndef __TOKENIZER_TABLE_H__
#define __TOKENIZER_TABLE_H__

#include "tokenizer.h"

static token_t *(*tokenization_table[3])(msg_t *msg) = {
	NULL,
	test_get_next_token,
	window_based_get_next_token,
};
#endif /* __TOKENIZER_TABLE_H__ */
