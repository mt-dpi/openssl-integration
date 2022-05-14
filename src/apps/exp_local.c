#include <stdlib.h>
#include <stdio.h>
#include <getopt.h>
#include <string.h>
#include <dpi/dpi.h>
#include <dpi/debug.h>

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

  unsigned long init_start_time, init_end_time;
  unsigned long te_start_time, te_end_time, te_total_time; 
  int te_count_time;
  unsigned long td_start_time, td_end_time, td_total_time; 
  int td_count_time;

  te_total_time = 0;
  td_total_time = 0;
  te_count_time = 0;
  td_count_time = 0;

  conf = init_conf_module();
  set_conf_module(conf, argc, argv);
  dpi = init_dpi_context(DPI_ROLE_MIDDLEBOX, conf);
  free_conf_module(conf);

  init_start_time = dpi_get_current_time();
  dpi_rule_preparation(dpi);
  init_end_time = dpi_get_current_time();

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

  do
  {
    token = dpi_get_next_token(dpi);
    if (token)
    {
      te_start_time = dpi_get_current_time();
      etoken = dpi_token_encryption(dpi, token);
      te_end_time = dpi_get_current_time();

      td_start_time = dpi_get_current_time();
      ret = dpi_token_detection(dpi, etoken);
      td_end_time = dpi_get_current_time();
      if (ret)
      {
        imsg(DPI_DEBUG_MIDDLEBOX, "Result: Found");
      }
      else
      {
        imsg(DPI_DEBUG_MIDDLEBOX, "Result: Not Found");
      }

      te_total_time += (te_end_time - te_start_time);
      td_total_time += (td_end_time - td_start_time);
      te_count_time++;
      td_count_time++;
    }
  } while (token);
  
  printf("DPI Name: %s\n", dpi_get_name(dpi));
  printf("# of Token Encryption: %d\n", te_count_time);
  printf("# of Token Detection: %d\n", td_count_time);

  printf("Rule Preparation: %lu us\n", init_end_time - init_start_time);
  printf("Token Encryption Time (%d): %.2f us\n", te_count_time, te_total_time / (double)te_count_time);
  printf("Token Detection Time (%d): %.2f us\n", td_count_time, td_total_time / (double)td_count_time);

  free_dpi_context(dpi);
  return 0;
}
