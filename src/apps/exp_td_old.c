#include <stdlib.h>
#include <stdio.h>
#include <getopt.h>
#include <string.h>
#include <unistd.h>
#include <dpi/dpi.h>
#include <dpi/debug.h>
#include "../etc/token.h"

#define COUNT 1000000
#define COUNTD 1000000.0

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
    if (!buf)
    {
      printf("error> out of memory\n");
      return 1;
    }
    fread(buf, 1, fsize, fp);

    fclose(fp);
  }
  else
  {
    emsg("error> file open error\n");
    return 1;
  }

  dpi_add_message(dpi, buf, fsize);

  token = dpi_get_next_token(dpi);
  if (token)
  {
    start = get_current_time();
    for (i=0; i<COUNT; i++)
    {
      etoken = dpi_token_encryption(dpi, token);
      iprint(DPI_DEBUG_MIDDLEBOX, "etoken", (etoken->value), 0, (etoken->len), 16);
      ret = dpi_token_detection(dpi, etoken);
      if (ret)
      {
        imsg(DPI_DEBUG_MIDDLEBOX, "Result: Found");
        printf("Result: Found\n");
      }
      else
      {
        imsg(DPI_DEBUG_MIDDLEBOX, "Result: Not Found");
        printf("Result: Not Found\n");
      }
    }
    end = get_current_time();
    val1 = (end - start) / COUNTD;
    printf("Averaged elapsed time (found) (token_encryption + token_detection): %.2lf ns\n", val1);

    start = get_current_time();
    for (i=0; i<COUNT; i++)
      dpi_token_encryption(dpi, token);
    end = get_current_time();
    val2 = (end - start) / COUNTD;
    printf("Averaged elapsed time (found) (token_encryption): %.2lf ns\n", val2);
    printf("Averaged elapsed time (found) (token_detection): %.2lf ns\n", val1 - val2);
  }
  
  token = dpi_get_next_token(dpi);
  if (token)
  {
    start = get_current_time();
    for (i=0; i<COUNT; i++)
    {
      etoken = dpi_token_encryption(dpi, token);
      ret = dpi_token_detection(dpi, etoken);
      if (ret)
      {
        imsg(DPI_DEBUG_MIDDLEBOX, "Result: Found");
        printf("Result: Found\n");
      }
      else
      {
        imsg(DPI_DEBUG_MIDDLEBOX, "Result: Not Found");
        printf("Result: Not Found\n");
      }
    }
    end = get_current_time();
    val1 = (end - start) / COUNTD;
    printf("Averaged elapsed time (not found) (token_encryption + token_detection): %.2lf ns\n", val1);

    start = get_current_time();
    for (i=0; i<COUNT; i++)
      dpi_token_encryption(dpi, token);
    end = get_current_time();
    val2 = (end - start) / COUNTD;
    printf("Averaged elapsed time (not found) (token_encryption): %.2lf ns\n", val2);
    printf("Averaged elapsed time (not found) (token_detection): %.2lf ns\n", val1 - val2);
  }

  free_dpi_context(dpi);
  return 0;
}
