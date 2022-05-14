#include <stdlib.h>
#include <stdio.h>
#include <getopt.h>
#include <string.h>
#include <dpi/dpi.h>
#include <dpi/debug.h>

int main(int argc, char *argv[])
{
  dpi_t *dpi1, *dpi2;
  conf_t *conf;

  conf = init_conf_module();
  set_conf_module(conf, argc, argv);

  dpi1 = init_dpi_context(DPI_ROLE_MIDDLEBOX, conf);
  dpi2 = init_dpi_context(DPI_ROLE_MIDDLEBOX, conf);
  free_conf_module(conf);

  printf("DPI Name: %s\n", dpi_get_name(dpi1));
  dpi_rule_preparation(dpi1);
  dpi_get_next_token(dpi1);
  dpi_token_encryption(dpi1, NULL);
  dpi_token_detection(dpi1, NULL);

  printf("DPI Name: %s\n", dpi_get_name(dpi2));
  dpi_rule_preparation(dpi2);
  dpi_get_next_token(dpi2);
  dpi_token_encryption(dpi2, NULL);
  dpi_token_detection(dpi2, NULL);

  free_dpi_context(dpi1);
  free_dpi_context(dpi2);

  return 0;
}
