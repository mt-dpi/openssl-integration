#include <dpi/debug.h>
#include <dpi/defines.h>
#include "rule_preparer.h"

int garbled_circuit_rule_preparation(dpi_t *dpi)
{
	fstart("dpi: %p", dpi);
	assert(dpi != NULL);

	int ret;
	ret = FAILURE;

	ffinish("ret: %d", ret);
	return ret;
}
