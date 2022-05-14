#include "token_encryptor_local.h"
#include "token_encryptor_table.h"
#include <dpi/debug.h>
#include <stdlib.h>
#include <string.h>

token_encryptor_t *init_token_encryptor(conf_t *conf)
{
  fstart("conf: %p", conf);
  assert(conf != NULL);

  int idx;
  token_encryptor_t *ret;

  idx = get_conf_module_token_encryption_idx(conf);
  ret = (token_encryptor_t *)calloc(1, sizeof(token_encryptor_t));
  ret->token_encryption = token_encryption_table[idx];

  ffinish("ret: %p", ret);
  return ret;
}

void free_token_encryptor(token_encryptor_t *module)
{
  fstart("module: %p", module);

  if (module)
  {
    free(module);
  }

  ffinish();
}
