#include <stdlib.h>
#include <stdio.h>
#include <getopt.h>
#include <string.h>
#include <unistd.h>
#include <dpi/dpi.h>
#include <dpi/debug.h>
#include "../etc/token.h"

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
  int ret, fsize;
  token_t *token;
  etoken_t *etoken;
  FILE *fp;
  const char *iname;
  unsigned long start, end;

  start = get_current_time();
  conf = init_conf_module();
  end = get_current_time();
  print_interval("init conf module", start, end);

  start = get_current_time();
  set_conf_module(conf, argc, argv);
  end = get_current_time();
  print_interval("set conf module", start, end);

  start = get_current_time();
  dpi = init_dpi_context(DPI_ROLE_MIDDLEBOX, conf);
  end = get_current_time();
  print_interval("init dpi context", start, end);

  start = get_current_time();
  free_conf_module(conf);
  end = get_current_time();
  print_interval("free conf module", start, end);

  start = get_current_time();
  dpi_rule_preparation(dpi);
  end = get_current_time();
  print_interval("dpi rule preparation", start, end);
  sleep(1);

  iname = dpi_get_input_filename(dpi);
  printf("input filename: %s\n", iname);
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

  printf("file load: %d bytes\n", fsize);
  dpi_add_message(dpi, buf, fsize);

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
  
  start = get_current_time();
  token = dpi_get_next_token(dpi);
  end = get_current_time();
  print_interval("dpi get next token", start, end);
  printf("token value: %s\n", get_token_value(token));
  if (token)
  {
    start = get_current_time();
    etoken = dpi_token_encryption(dpi, token);
    end = get_current_time();
    print_interval("dpi token encryption", start, end);

    start = get_current_time();
    ret = dpi_token_detection(dpi, etoken);
    end = get_current_time();
    print_interval("dpi token detection", start, end);
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

  start = get_current_time();
  token = dpi_get_next_token(dpi);
  end = get_current_time();
  print_interval("dpi get next token", start, end);
  printf("token value: %s\n", get_token_value(token));
  if (token)
  {
    start = get_current_time();
    etoken = dpi_token_encryption(dpi, token);
    end = get_current_time();
    print_interval("dpi token encryption", start, end);

    start = get_current_time();
    ret = dpi_token_detection(dpi, etoken);
    end = get_current_time();
    print_interval("dpi token detection", start, end);
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

  start = get_current_time();
  free_dpi_context(dpi);
  end = get_current_time();
  print_interval("free dpi context", start, end);
  return 0;
}
