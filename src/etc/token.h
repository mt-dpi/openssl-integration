#ifndef __TOKEN_H__
#define __TOKEN_H__

#include <dpi/dpi_types.h>

struct token_st
{
  uint8_t *value;
  int len;
};

struct etoken_st
{
  uint8_t *value;
  uint8_t cid;
  int len;
};

unsigned int token_hash(token_t *token);
token_t *init_token(void);
void set_token_value(token_t *token, uint8_t *val, int len, int bsize);
uint8_t *get_token_value(token_t *token);
int get_token_length(token_t *token);
void free_token(token_t *token);

unsigned int etoken_hash(etoken_t *etoken);
etoken_t *init_etoken(uint8_t *val, int len);
void update_etoken(etoken_t *etoken, uint8_t *val, int len);
void set_etoken_cid(etoken_t *etoken, uint8_t cid);
uint8_t *get_etoken_value(etoken_t *etoken);
int get_etoken_length(etoken_t *etoken);
uint8_t get_etoken_cid(etoken_t *etoken);
void free_etoken(etoken_t *token);

#endif /* __TOKEN_H__ */
