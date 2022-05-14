#ifndef __MESSAGE_H__
#define __MESSAGE_H__

#include <dpi/params.h>
#include <stdint.h>

typedef struct msg_st
{
  int processed;
  uint8_t *msg;
  int mlen;
  int offset;
  int bsize;
  param_t *param;
  struct msg_st *next;
} msg_t;

msg_t *init_message(uint8_t *msg, int mlen, int bsize, param_t *param);
void free_messages(msg_t *head);
void free_message(msg_t *msg);
#endif /* __MESSAGE_H__ */
