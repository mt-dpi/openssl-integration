#include <string.h>
#include <stdio.h>
#include "../token_detector/token_detector.h"
#include <dpi/dpi.h>
#include <dpi/debug.h>

#define TEST_WINDOW_SIZE 8
#define TEST_RS_VALUE 5
#define TEST_RULE_FILE "../../data/test.txt"

int main(int argc, char *argv[])
{
  dpi_t *dpi;
  conf_t *conf;
  const uint8_t *test = (const uint8_t *)"alice apple";
  int ret, len;
  uint8_t *value;
  token_t *token;
  etoken_t *etoken;

  conf = init_conf_module();
  set_conf_module(conf, argc, argv);
  dpi = init_dpi_context(DPI_ROLE_MIDDLEBOX, conf);
  free_conf_module(conf);
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
      ret = dpi_token_detection(dpi, etoken);
      imsg(DPI_DEBUG_MIDDLEBOX, "Result: %d", ret);
    }
  } while (token);

  free_dpi_context(dpi);
  return 0;
}
