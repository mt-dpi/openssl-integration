#include "table.h"
#include <dpi/debug.h>
#include <string.h>
#include <stdlib.h>

entry_t *init_entry(token_t *token)
{
  fstart("token: %p", token);
  assert(token != NULL);

  entry_t *ret;
  ret = (entry_t *)calloc(1, sizeof(entry_t));
  ret->token = token;

  ffinish("ret: %p", ret);
  return ret;
}

hentry_t *init_hentry(etoken_t *handle)
{
  fstart("handle: %p", handle);
  assert(handle != NULL);

  hentry_t *ret;
  ret = (hentry_t *)calloc(1, sizeof(hentry_t));
  ret->handle = handle;

  ffinish("ret: %p", ret);
  return ret;
}
