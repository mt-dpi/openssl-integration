#include "token_detector_local.h"
#include "token_detector_table.h"
#include <dpi/debug.h>
#include <stdlib.h>
#include <string.h>

token_detector_t *init_token_detector(conf_t *conf)
{
  fstart("conf: %p", conf);
  assert(conf != NULL);

  int idx;
  token_detector_t *ret;

  idx = get_conf_module_token_detection_idx(conf);
  ret = (token_detector_t *)calloc(1, sizeof(token_detector_t));
  ret->token_detection = token_detection_table[idx];

  ffinish("ret: %p", ret);
  return ret;
}

void free_token_detector(token_detector_t *module)
{
  fstart("module: %p", module);

  if (module)
  {
    free(module);
  }

  ffinish();
}
