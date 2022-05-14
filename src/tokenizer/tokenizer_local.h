#ifndef __TOKENIZER_LOCAL_H__
#define __TOKENIZER_LOCAL_H__

#include "tokenizer.h"
#include "../etc/token.h"
#include "../etc/message.h"

struct tokenizer_st
{
  msg_t *(*init_message)(uint8_t *msg, int mlen, param_t *param);
  void (*free_message)(msg_t *msg);
  token_t *(*get_next_token)(msg_t *msg);
  void (*free_token)(token_t *tok);
};

#endif /* __TOKENIZER_LOCAL_H__ */
