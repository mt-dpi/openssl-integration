#include <stdlib.h>
#include <stdio.h>
#include <getopt.h>
#include <string.h>
#include <unistd.h>
#include <dpi/dpi.h>
#include <dpi/debug.h>
#include "../etc/token.h"

int main(int argc, char *argv[])
{
  dpi_t *dpi;
  conf_t *conf;
  uint8_t *buf;
  int ret, fsize, i;
  token_t *token;
  etoken_t *etoken;
  FILE *fp;
  const char *iname;
  unsigned long start, end;
  double val1, val2;

  conf = init_conf_module();
  set_conf_module(conf, argc, argv);
  dpi = init_dpi_context(DPI_ROLE_MIDDLEBOX, conf);
  free_conf_module(conf);
  dpi_rule_preparation(dpi);
  sleep(1);

  iname = dpi_get_input_filename(dpi);
  fp = fopen(iname, "r");
  if (fp)
  {
    fseek(fp, 0, SEEK_END);
    fsize = ftell(fp);
    rewind(fp);

    buf = (uint8_t *)malloc(fsize);
    fread(buf, 1, fsize, fp);

    fclose(fp);
  }

  dpi_add_message(dpi, buf, fsize);

  for (i=0; i<1200; i++)
  {
    token = dpi_get_next_token(dpi);
    if (token)
    {
      etoken = dpi_token_encryption(dpi, token);
      ret = dpi_token_detection(dpi, etoken);
      if (ret)
      {
        imsg(DPI_DEBUG_MIDDLEBOX, "Result: Found");
        printf("Result: Found\n\n");
      }
      else
      {
        imsg(DPI_DEBUG_MIDDLEBOX, "Result: Not Found");
        printf("Result: Not Found\n\n");
      }
    }
  }

  free_dpi_context(dpi);
  return 0;
}
