#include "token.h"
#include <dpi/debug.h>
#include <stdlib.h>
#include <string.h>

unsigned int token_hash(token_t *token)
{
  fstart("token: %p", token);

  uint8_t *str;
  int len;
  unsigned int hash = 0;
  unsigned int x = 0;
  unsigned int i = 0;

  str = token->value;
  len = dpi_get_token_length(token);

  for (i=0; i<len; str++, i++)
  {
    hash = (hash << 4) + (*str);

    if ((x = hash & 0xF0000000L) != 0)
    {
      hash ^= (x >> 24);
    }

    hash &= ~x;
  }

  ffinish("hash: %u", hash);
  return hash;
}

unsigned int etoken_hash(etoken_t *etoken)
{
  fstart("etoken: %p", etoken);

  uint8_t *str;
  int len;
  unsigned int hash = 0;
  unsigned int x = 0;
  unsigned int i = 0;

  str = etoken->value;
  len = dpi_get_encrypted_token_length(etoken);

  for (i=0; i<len; str++, i++)
  {
    hash = (hash << 4) + (*str);

    if ((x = hash & 0xF0000000L) != 0)
    {
      hash ^= (x >> 24);
    }

    hash &= ~x;
  }

  ffinish("hash: %u", hash);
  return hash;
}

token_t *init_token(void)
{
  fstart();

  token_t *ret;
  ret = (token_t *)calloc(1, sizeof(token_t));

  ffinish("ret: %p", ret);
  return ret;
}

void set_token_value(token_t *token, uint8_t *val, int len, int blk)
{
  fstart("token: %p, val: %p, len: %d, blk: %d", token, val, len, blk);

  token->value = (uint8_t *)calloc(1, blk);
  token->len = blk;
  memcpy(token->value, val, len);

  ffinish();
}

uint8_t *get_token_value(token_t *token)
{
  fstart("token: %p", token);
  assert(token != NULL);

  uint8_t *ret;
  ret = token->value;

  ffinish("ret: %p", ret);
  return ret;
}

int get_token_length(token_t *token)
{
  fstart("token: %p", token);
  assert(token != NULL);

  int ret;
  ret = token->len;

  ffinish("ret: %d", ret);
  return ret;
}

void free_token(token_t *token)
{
  fstart("token: %p", token);
  assert(token != NULL);

  if (token)
  {
    if (token->value)
      free(token->value);
    free(token);
  }

  ffinish();
}

etoken_t *init_etoken(uint8_t *val, int len)
{
  fstart("val: %p, len: %d", val, len);

  etoken_t *ret;
  ret = (etoken_t *)calloc(1, sizeof(etoken_t));
  ret->value = (uint8_t *)calloc(1, len);
  ret->len = len;
  memcpy(ret->value, val, len);

  ffinish("ret: %p", ret);
  return ret;
}

void update_etoken(etoken_t *etoken, uint8_t *val, int len)
{
  fstart("etoken: %p, val: %p, len: %d", etoken, val, len);
  assert(val != NULL);

  etoken->value = val;
  etoken->len = len;

  ffinish();
}

void set_etoken_cid(etoken_t *etoken, uint8_t cid)
{
  fstart("etoken: %p, cid: %d", etoken, cid);
  assert(etoken != NULL);

  etoken->cid = cid;

  ffinish();
}

uint8_t *get_etoken_value(etoken_t *etoken)
{
  fstart("etoken: %p", etoken);
  assert(etoken != NULL);

  uint8_t *ret;
  ret = etoken->value;

  ffinish("ret: %p", ret);
  return ret;
}

int get_etoken_length(etoken_t *etoken)
{
  fstart("etoken: %p", etoken);
  assert(etoken != NULL);

  int ret;
  ret = etoken->len;

  ffinish("ret: %d", ret);
  return ret;
}

uint8_t get_etoken_cid(etoken_t *etoken)
{
  fstart("etoken: %p", etoken);
  assert(etoken != NULL);

  uint8_t ret;
  ret = etoken->cid;

  ffinish("ret: %d", ret);
  return ret;
}

void free_etoken(etoken_t *token)
{
  fstart("token: %p", token);
  assert(token != NULL);
  
  if (token)
  {
    if (token->value)
    {
      free(token->value);
    }
    free(token);
  }

  ffinish();
}
