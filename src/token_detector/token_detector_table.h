#ifndef __TOKEN_DETECTOR_TABLE_H__
#define __TOKEN_DETECTOR_TABLE_H__

#include "token_detector.h"

static int (*token_detection_table[8])(dpi_t *dpi, etoken_t *etoken) = {
	NULL,
	test_token_detection,
	nonfixedkey_cluster_token_detection,
	fixedkey_cluster_token_detection,
	fixedkey_perkeyword_token_detection,
	fixedkey_global_token_detection,
	nonfixedkey_perkeyword_token_detection,
	nonfixedkey_global_token_detection,
};
#endif /* __TOKEN_DETECTOR_TABLE_H__ */
