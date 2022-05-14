#include <dpi/debug.h>
#include <dpi/defines.h>
#include "token_detector.h"

int test_token_detection(dpi_t *dpi, etoken_t *etoken)
{
	fstart("dpi: %p, etoken: %p", dpi, etoken);
	assert(dpi != NULL);
	assert(etoken != NULL);

	int ret;
	ret = FALSE;

  imsg(DPI_DEBUG_MIDDLEBOX, "This is the test function for the token detection");

	ffinish("ret: %d", ret);
	return ret;
}
