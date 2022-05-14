#include <stdlib.h>
#include <stdio.h>
#include <getopt.h>
#include <string.h>
#include <unistd.h>
#include <dpi/dpi.h>
#include <dpi/debug.h>
#include "../etc/token.h"

#define COUNT 100
#define COUNTD 100.0

#define print_interval(m, a, b) \
  printf("%s: %lu ns\n", m, b - a);

unsigned long get_current_time(void)
{
  struct timespec ts;
  clock_gettime(CLOCK_MONOTONIC, &ts);
  return ts.tv_sec * 1000000000 + ts.tv_nsec;
}

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
  double val1, val2, val3;

  conf = init_conf_module();
  set_conf_module(conf, argc, argv);
  dpi = init_dpi_context(DPI_ROLE_MIDDLEBOX, conf);
  free_conf_module(conf);
  dpi_rule_preparation(dpi);
  sleep(3);

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

  start = get_current_time();
  for (i=0; i<COUNT; i++)
  {
    token = dpi_get_next_token(dpi);
    if (token)
    {
      etoken = dpi_token_encryption(dpi, token);
      ret = dpi_token_detection(dpi, etoken);
      if (ret)
      {
        imsg(DPI_DEBUG_MIDDLEBOX, "Result: Found");
      }
      else
      {
        imsg(DPI_DEBUG_MIDDLEBOX, "Result: Not Found");
      }
    }
  }
  end = get_current_time();
  val1 = (end - start) / COUNTD;
  printf("Averaged elapsed time (get next token + token encryption + token detection): %.2lf ns\n", val1);

  start = get_current_time();
  for (i=0; i<COUNT; i++)
    dpi_token_encryption(dpi, token);
  end = get_current_time();
  val2 = (end - start) / COUNTD;

  start = get_current_time();
  for (i=0; i<COUNT; i++)
    dpi_get_next_token(dpi);
  end = get_current_time();
  val3 = (end - start) / COUNTD;

  printf("Averaged elapsed time (get next token): %.2lf ns\n", val3);
  printf("Averaged elapsed time (token encryption): %.2lf ns\n", val2);
  printf("Averaged elapsed time (token detection): %.2lf ns\n", val1 - val2 - val3);

  free_dpi_context(dpi);
  return 0;
}
