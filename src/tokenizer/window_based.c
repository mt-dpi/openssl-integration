#include <dpi/debug.h>
#include <dpi/defines.h>
#include <string.h>
#include "tokenizer_local.h"

token_t *window_based_get_next_token(msg_t *msg)
{
  fstart("msg: %p", msg);
  assert(msg != NULL);

  uint8_t *p, *tmp;
  token_t *ret;
  int mlen, wlen, bsize, offset;

  ret = NULL;
  p = msg->msg;
  mlen = msg->mlen;
  wlen = msg->param->wlen;
  offset = msg->offset;
  bsize = msg->bsize;

  if (wlen <= (mlen - offset))
  {
    ret = init_token();
    set_token_value(ret, p + offset, wlen, bsize);

    msg->offset++;
  }
  else if (mlen - offset > 0)
  {
    ret = init_token();
    tmp = (uint8_t *)calloc(1, wlen);
    memcpy(tmp, p + offset, mlen - offset);
    set_token_value(ret, tmp, wlen, bsize);
    free(tmp);
    msg->offset++;
  }

  ffinish("ret: %p", ret);
  return ret;
}

