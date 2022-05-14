#include <dpi/debug.h>
#include <dpi/defines.h>
#include "token_encryptor.h"

etoken_t *test_token_encryption(dpi_t *dpi, token_t *token)
{
	fstart("dpi: %p, token: %p", dpi, token);
	assert(dpi != NULL);

	etoken_t *ret;
	ret = NULL;

  imsg(DPI_DEBUG_MIDDLEBOX, "This is the function for the token encryption");

	ffinish("ret: %p", ret);
	return ret;
}
