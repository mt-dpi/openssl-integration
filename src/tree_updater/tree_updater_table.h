#ifndef __TREE_UPDATER_TABLE_H__
#define __TREE_UPDATER_TABLE_H__

#include "tree_updater.h"

static int (*tree_update_table[8])(dpi_t *dpi, etoken_t *etoken, int idx, int result, int cvalue) = {
	NULL,
	test_tree_update,
	nonfixedkey_cluster_tree_update,
	fixedkey_cluster_tree_update,
	fixedkey_perkeyword_tree_update,
	fixedkey_global_tree_update,
	nonfixedkey_perkeyword_tree_update,
	nonfixedkey_global_tree_update,
};
#endif /* __TREE_UPDATER_TABLE_H__ */
