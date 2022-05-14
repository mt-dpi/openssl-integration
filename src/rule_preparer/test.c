#include <dpi/debug.h>
#include <dpi/defines.h>
#include "rule_preparer.h"

int test_rule_preparation(dpi_t *dpi)
{
	fstart("dpi: %p", dpi);
	assert(dpi != NULL);

	int ret;
	ret = FAILURE;
  
  imsg(DPI_DEBUG_MIDDLEBOX, "This is the test function for the rule preparation");

	ffinish("ret: %d", ret);
	return ret;
}
