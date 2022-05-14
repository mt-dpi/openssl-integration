#include <string.h>
#include <stdio.h>
#include "../token_encryptor/token_encryptor.h"
#include <dpi/dpi.h>
#include <dpi/debug.h>

#define TEST_WINDOW_SIZE 8
#define TEST_RS_VALUE 5

int main(int argc, char *argv[])
{
  dpi_t *dpi;
  conf_t *conf;
  const uint8_t *test = (const uint8_t *)"alice apple";
  int len;
  uint8_t *value;
  token_t *token;
  etoken_t *etoken;

  conf = init_conf_module();
  set_conf_module(conf, argc, argv);

  dpi = init_dpi_context(DPI_ROLE_MIDDLEBOX, conf);
  dpi_add_message(dpi, (uint8_t *)test, strlen((const char *)test));

  do
  {
    token = dpi_get_next_token(dpi);
    if (token)
    {
      etoken = dpi_token_encryption(dpi, token);
      imsg(DPI_DEBUG_MIDDLEBOX, "Token: %s", dpi_get_token_value(token));
      value = dpi_get_encrypted_token_value(etoken);
      len = dpi_get_encrypted_token_length(etoken);
      iprint(DPI_DEBUG_MIDDLEBOX, "Encrypted Token", value, 0, len, 16);
    }
  } while (token);

  return 0;
}
