#ifndef __TOKENIZER_H__
#define __TOKENIZER_H__

#include <dpi/dpi.h>
#include <dpi/dpi_types.h>
#include <dpi/debug.h>
#include "tokenizer_local.h"

#define NONE_TOKENIZER_IDX 0
#define TEST_TOKENIZER_IDX 1
#define WINDOW_BASED_TOKENIZER_IDX 2

tokenizer_t *init_tokenizer(conf_t *conf);
void free_tokenizer(tokenizer_t *module);
token_t *test_get_next_token(msg_t *msg);
token_t *window_based_get_next_token(msg_t *msg);

#endif /* __TOKENIZER_H__ */
