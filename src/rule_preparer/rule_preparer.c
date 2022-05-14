#include "rule_preparer_local.h"
#include "rule_preparer_table.h"
#include <dpi/debug.h>
#include <stdlib.h>
#include <string.h>

rule_preparer_t *init_rule_preparer(conf_t *conf)
{
  fstart("conf: %p", conf);
  assert(conf != NULL);

  int idx;
  rule_preparer_t *ret;

  idx = get_conf_module_rule_preparation_idx(conf);
  ret = (rule_preparer_t *)calloc(1, sizeof(rule_preparer_t));
  ret->rule_preparation = rule_preparation_table[idx];

  ffinish("ret: %p", ret);
  return ret;
}

void free_rule_preparer(rule_preparer_t *module)
{
  fstart("module: %p", module);

  if (module)
  {
    free(module);
  }

  ffinish();
}
