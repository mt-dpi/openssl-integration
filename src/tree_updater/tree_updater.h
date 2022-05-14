#ifndef __TREE_UPDATER_H__
#define __TREE_UPDATER_H__

#include <dpi/dpi.h>
#include <dpi/dpi_types.h>
#include <dpi/debug.h>
#include "tree_updater_local.h"

#define NONE_TREE_UPDATER_IDX 0
#define TEST_TREE_UPDATER_IDX 1
#define NONFIXEDKEY_CLUSTER_TREE_UPDATER_IDX 2
#define FIXEDKEY_CLUSTER_TREE_UPDATER_IDX 3
#define FIXEDKEY_PERKEYWORD_TREE_UPDATER_IDX 4
#define FIXEDKEY_GLOBAL_TREE_UPDATER_IDX 5
#define NONFIXEDKEY_PERKEYWORD_TREE_UPDATER_IDX 6
#define NONFIXEDKEY_GLOBAL_TREE_UPDATER_IDX 7

tree_updater_t *init_tree_updater(conf_t *conf);
void free_tree_updater(tree_updater_t *module);
int test_tree_update(dpi_t *dpi, etoken_t *etoken, int idx, int result, int cvalue);
int nonfixedkey_cluster_tree_update(dpi_t *dpi, etoken_t *etoken, int idx, int result, int cvalue);
int fixedkey_cluster_tree_update(dpi_t *dpi, etoken_t *etoken, int idx, int result, int cvalue);
int fixedkey_perkeyword_tree_update(dpi_t *dpi, etoken_t *etoken, int idx, int result, int cvalue);
int fixedkey_global_tree_update(dpi_t *dpi, etoken_t *etoken, int idx, int result, int cvalue);
int nonfixedkey_perkeyword_tree_update(dpi_t *dpi, etoken_t *etoken, int idx, int result, int cvalue);
int nonfixedkey_global_tree_update(dpi_t *dpi, etoken_t *etoken, int idx, int result, int cvalue);

#endif /* __TREE_UPDATER_H__ */
