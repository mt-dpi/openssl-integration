#ifndef __RULE_PREPARER_H__
#define __RULE_PREPARER_H__

#include <dpi/dpi.h>
#include <dpi/dpi_types.h>
#include <dpi/debug.h>
#include "rule_preparer_local.h"

#define NONE_RULE_PREPARER_IDX 0
#define TEST_RULE_PREPARER_IDX 1
#define NONFIXEDKEY_CLUSTER_RULE_PREPARER_IDX 2
#define FIXEDKEY_CLUSTER_RULE_PREPARER_IDX 3
#define CIRCUIT_RANDOMIZATION_RULE_PREPARER_IDX 4
#define FIXEDKEY_PERKEYWORD_RULE_PREPARER_IDX 5
#define FIXEDKEY_GLOBAL_RULE_PREPARER_IDX 6
#define GARBLED_CIRCUIT_RULE_PREPARER_IDX 7
#define NONFIXEDKEY_PERKEYWORD_RULE_PREPARER_IDX 8
#define NONFIXEDKEY_GLOBAL_RULE_PREPARER_IDX 9

rule_preparer_t *init_rule_preparer(conf_t *conf);
void free_rule_preparer(rule_preparer_t *module);
int test_rule_preparation(dpi_t *dpi);
int nonfixedkey_cluster_rule_preparation(dpi_t *dpi);
int fixedkey_cluster_rule_preparation(dpi_t *dpi);
int circuit_randomization_rule_preparation(dpi_t *dpi);
int fixedkey_perkeyword_rule_preparation(dpi_t *dpi);
int fixedkey_global_rule_preparation(dpi_t *dpi);
int garbled_circuit_rule_preparation(dpi_t *dpi);
int nonfixedkey_perkeyword_rule_preparation(dpi_t *dpi);
int nonfixedkey_global_rule_preparation(dpi_t *dpi);

#endif /* __RULE_PREPARER_H__ */
