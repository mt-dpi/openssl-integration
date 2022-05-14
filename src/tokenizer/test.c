#include <dpi/debug.h>
#include <dpi/defines.h>
#include "tokenizer.h"

token_t *test_get_next_token(msg_t *msg)
{
	fstart("msg: %p", msg);

	token_t *ret;
	ret = NULL;

  imsg(DPI_DEBUG_MIDDLEBOX, "This is the test function for the tokenizer");

	ffinish("ret: %p", ret);
	return ret;
}
