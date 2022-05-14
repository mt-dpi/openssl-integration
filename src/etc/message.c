#include "message.h"
#include <dpi/debug.h>
#include <stdlib.h>
#include <string.h>

msg_t *init_message(uint8_t *msg, int mlen, int bsize, param_t *param)
{
  fstart("msg: %p, mlen: %d, bsize: %d, param: %p", msg, mlen, bsize, param);
  assert(msg != NULL);
  assert(mlen > 0);
  assert(bsize > 0);
  assert(param != NULL);

  msg_t *ret;
  ret = (msg_t *)calloc(1, sizeof(msg_t));
  ret->msg = (uint8_t *)calloc(1, mlen);
  ret->mlen = mlen;
  ret->bsize = bsize;
  ret->param = param;
  memcpy(ret->msg, msg, mlen);
  
  ffinish("ret: %p", ret);
  return ret;
}

void free_message(msg_t *msg)
{
  fstart("msg: %p", msg);
  assert(msg != NULL);

  if (msg)
  {
    if (msg->msg)
    {
      free(msg->msg);
      msg->msg = NULL;
      msg->mlen = 0;
    }
    free(msg);
  }

  ffinish();
}

void free_messages(msg_t *head)
{
  fstart("head: %p", head);
  assert(head != NULL);

  msg_t *msg;
  msg = head;

  if (msg)
  {
    if (msg->next)
      free_messages(msg->next);
    free_message(msg);
  }

  ffinish();
}
