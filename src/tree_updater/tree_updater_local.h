#ifndef __TREE_UPDATER_LOCAL_H__
#define __TREE_UPDATER_LOCAL_H__

#include "../etc/broker.h"
#include "../etc/search_tree.h"

typedef struct tree_updater_st
{
  broker_t *broker;
  int num_of_trees;
  int num_of_clusters;
  int *idx;
  search_tree_t **trees;
  int *active;
  int *cvalue;
  int (*tree_update)(dpi_t *dpi, etoken_t *etoken, int idx, int result, int counter);
} tree_updater_t;

#endif /* __TREE_UPDATE_LOCAL_H__ */
