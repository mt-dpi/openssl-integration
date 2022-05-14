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
  int ret, fsize, i, nentries;
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
  sleep(1);

  nentries = get_conf_exp_prev_num_of_entries(conf);
  printf("# of previously inserted entries in the counter table: %d\n", nentries);

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

  start = get_current_time();
  for (i=0; i<100; i++)
  {
    token = dpi_get_next_token(dpi);
    etoken = dpi_token_encryption(dpi, token);
  }
  end = get_current_time();
  val1 = (end - start) / 100.0;
  printf("Averaged elapsed time (get_next_token + token_encryption): %.2lf ns\n", val1);

  start = get_current_time();
  for (i=0; i<100; i++)
  {
    token = dpi_get_next_token(dpi);
  }
  end = get_current_time();
  val2 = (end - start) / 100.0;
  printf("Averaged elapsed time (get_next_token): %.2lf ns\n", val2);
  val3 = val1 - val2;
  printf("Averaged elapsed time (token_encryption): %.2lf ns\n", val3);

  return 0;
}
