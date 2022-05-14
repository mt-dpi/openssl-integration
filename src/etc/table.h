#ifndef __TABLE_H__
#define __TABLE_H__

#include <dpi/dpi_types.h>

typedef struct entry_st
{
  token_t *token;
  uint8_t count;
  struct entry_st *next;
} entry_t;

typedef struct bucket_st
{
  int num;
  entry_t *head;
} bucket_t;

typedef struct hentry_st
{
  etoken_t *handle;
  uint8_t count;
  struct hentry_st *next;
} hentry_t;

typedef struct hbucket_st
{
  int num;
  hentry_t *head;
} hbucket_t;

entry_t *init_entry(token_t *token);
hentry_t *init_hentry(etoken_t *handle);

#endif /* __TABLE_H__ */
