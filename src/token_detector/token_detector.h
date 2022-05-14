#ifndef __TOKEN_DETECTOR_H__
#define __TOKEN_DETECTOR_H__

#include <dpi/dpi.h>
#include <dpi/dpi_types.h>
#include <dpi/debug.h>
#include "token_detector_local.h"

#define NONE_TOKEN_DETECTOR_IDX 0
#define TEST_TOKEN_DETECTOR_IDX 1
#define NONFIXEDKEY_CLUSTER_TOKEN_DETECTOR_IDX 2
#define FIXEDKEY_CLUSTER_TOKEN_DETECTOR_IDX 3
#define FIXEDKEY_PERKEYWORD_TOKEN_DETECTOR_IDX 4
#define FIXEDKEY_GLOBAL_TOKEN_DETECTOR_IDX 5
#define NONFIXEDKEY_PERKEYWORD_TOKEN_DETECTOR_IDX 6
#define NONFIXEDKEY_GLOBAL_TOKEN_DETECTOR_IDX 7

token_detector_t *init_token_detector(conf_t *conf);
void free_token_detector(token_detector_t *module);
int test_token_detection(dpi_t *dpi, etoken_t *etoken);
int nonfixedkey_cluster_token_detection(dpi_t *dpi, etoken_t *etoken);
int fixedkey_cluster_token_detection(dpi_t *dpi, etoken_t *etoken);
int fixedkey_perkeyword_token_detection(dpi_t *dpi, etoken_t *etoken);
int fixedkey_global_token_detection(dpi_t *dpi, etoken_t *etoken);
int nonfixedkey_perkeyword_token_detection(dpi_t *dpi, etoken_t *etoken);
int nonfixedkey_global_token_detection(dpi_t *dpi, etoken_t *etoken);

#endif /* __TOKEN_DETECTOR_H__ */
