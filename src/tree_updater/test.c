#include <dpi/debug.h>
#include <dpi/defines.h>
#include "tree_updater.h"

int test_tree_update(dpi_t *dpi, etoken_t *etoken, int idx, int result, int cvalue)
{
	fstart("dpi: %p, etoken: %p, idx: %d, result: %d, cvalue: %d", dpi, etoken, idx, result, cvalue);
	assert(dpi != NULL);

	int ret;
	ret = FALSE;

  printf("test tree update\n");

	ffinish("ret: %d", ret);
	return ret;
}
