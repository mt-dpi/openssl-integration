#include <string.h>
#include <stdio.h>
#include "../tokenizer/tokenizer.h"
#include <dpi/dpi.h>
#include <dpi/debug.h>

#define TEST_WINDOW_SIZE 8

int main(int argc, char *argv[])
{
  dpi_t *dpi;
  conf_t *conf;
  const uint8_t *test = (const uint8_t *)"alice apple";
  token_t *token;

  conf = init_conf_module();
  set_conf_module(conf, argc, argv);

  dpi = init_dpi_context(DPI_ROLE_MIDDLEBOX, conf);
  free_conf_module(conf);

  dpi_add_message(dpi, (uint8_t *)test, strlen((const char *)test));

  do
  {
    token = dpi_get_next_token(dpi);
    if (token)
      printf("Token: %s\n", dpi_get_token_value(token));
  } while (token);

  return 0;
}
