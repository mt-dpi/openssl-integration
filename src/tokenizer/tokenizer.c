#include "tokenizer_local.h"
#include "tokenizer_table.h"
#include <string.h>
#include <stdlib.h>
#include <dpi/debug.h>

tokenizer_t *init_tokenizer(conf_t *conf)
{
  fstart("conf: %p", conf);
  assert(conf != NULL);

  int idx;
  tokenizer_t *ret;

  idx = get_conf_module_get_next_token_idx(conf);
  ret = (tokenizer_t *)calloc(1, sizeof(tokenizer_t));
  ret->get_next_token = tokenization_table[idx];

  ffinish("ret: %p", ret);
  return ret;
}

void free_tokenizer(tokenizer_t *module)
{
  fstart("module: %p", module);

  if (module)
  {
    free(module);
  }

  ffinish();
}
