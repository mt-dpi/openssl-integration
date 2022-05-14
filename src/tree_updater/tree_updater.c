#include "tree_updater_local.h"
#include "tree_updater_table.h"
#include <dpi/debug.h>
#include <stdlib.h>
#include <string.h>

tree_updater_t *init_tree_updater(conf_t *conf)
{
  fstart("conf: %p", conf);
  assert(conf != NULL);

  int i, idx, num_of_trees, num_of_clusters;
  tree_updater_t *ret;

  idx = get_conf_module_tree_update_idx(conf);
  num_of_trees = get_conf_param_num_of_trees(conf);
  num_of_clusters = get_conf_param_num_of_clusters(conf);

  ret = (tree_updater_t *)calloc(1, sizeof(tree_updater_t));
  ret->broker = init_broker();
  ret->tree_update = tree_update_table[idx];
  ret->num_of_trees = num_of_trees;
  ret->num_of_clusters = num_of_clusters;
  ret->trees = (search_tree_t **)calloc(num_of_trees, sizeof(search_tree_t *));
  ret->cvalue = (int *)calloc(num_of_clusters, sizeof(int));
  ret->active = (int *)calloc(num_of_trees, sizeof(int));
  ret->idx = (int *)calloc(num_of_clusters, sizeof(int));

  for (i=0; i<num_of_clusters; i++)
    ret->idx[i] = i;

  for (i=0; i<num_of_clusters; i++)
    ret->cvalue[i] = -1;

  ffinish("ret: %p", ret);
  return ret;
}

void free_tree_updater(tree_updater_t *module)
{
  fstart("module: %p", module);

  int i;

  if (module)
  {
    for (i=0; i<module->num_of_trees; i++)
    {
      if (module->trees)
        free_search_tree(module->trees[i]);
    }
    free(module);
  }

  ffinish();
}
