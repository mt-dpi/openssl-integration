#ifndef __RULE_PREPARER_TABLE_H__
#define __RULE_PREPARER_TABLE_H__

#include "rule_preparer.h"

static int (*rule_preparation_table[10])(dpi_t *dpi) = {
	NULL,
	test_rule_preparation,
	nonfixedkey_cluster_rule_preparation,
	fixedkey_cluster_rule_preparation,
	circuit_randomization_rule_preparation,
	fixedkey_perkeyword_rule_preparation,
	fixedkey_global_rule_preparation,
	garbled_circuit_rule_preparation,
	nonfixedkey_perkeyword_rule_preparation,
	nonfixedkey_global_rule_preparation,
};
#endif /* __RULE_PREPARER_TABLE_H__ */
