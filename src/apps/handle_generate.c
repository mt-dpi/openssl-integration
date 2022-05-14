#include <stdlib.h>
#include <stdio.h>
#include <getopt.h>
#include <string.h>
#include <dpi/dpi.h>
#include <dpi/debug.h>
#include <dpi/defines.h>
#include <dpi/setting.h>
#include "../etc/handle_table.h"
#include "../etc/token.h"

int main(int argc, char *argv[])
{
  int i, j, num, dtype;
  dpi_t *dpi;
  conf_t *conf;
  handle_table_t *table;
  hbucket_t *bucket;
  hentry_t *entry;
  etoken_t *handle;
  FILE *fp;
  size_t nlen;
  const char *name;
  unsigned char fname[256] = {0, };
  unsigned char buf[5];
  unsigned char *p;

  dtype = DPI_DEBUG_MIDDLEBOX;
  conf = init_conf_module();
  set_conf_module(conf, argc, argv);

  dpi = init_dpi_context(DPI_ROLE_MIDDLEBOX, conf);
  free_conf_module(conf);

  name = dpi_get_name(dpi);
  printf("DPI Name: %s\n", name);
  dpi_rule_preparation(dpi);

  table = dpi_get_handle_table(dpi);

  nlen = strlen(name);
  snprintf(fname, nlen + 5, "%s.txt", name);
  printf("output file name: %s\n", fname);
  fp = fopen(fname, "wb");
  if (!fp)
  {
    printf("file open error\n");
    return 1;
  }

  printf("# of entries: %d\n", table->num_of_entries);
  p = buf;
  VAR_TO_PTR_4BYTES((table->num_of_entries), p);

  fwrite(buf, 1, 4, fp);
  for (i=0; i<NUM_OF_BUCKETS; i++)
  {
    bucket = table->buckets[i];
    num = bucket->num;
    entry = bucket->head;

    for (j=0; j<num; j++)
    {
      handle = entry->handle;
      iprint(DPI_DEBUG_MIDDLEBOX, "Handle", (handle->value), 0, (handle->len), (handle->len));
      fwrite(handle->value, 1, (handle->len), fp); 
      entry = entry->next;
    }
  }

  fclose(fp);
  free_handle_table(table);
  printf("finish encoding to the file\n");

  table = init_handle_table();
  fp = fopen(fname, "rb");
  fread(buf, 4, 1, fp);
  p = buf;
  PTR_TO_VAR_4BYTES(p, num);
  printf("# of entries: %d\n", num);

  for (i=0; i<num; i++)
  {
    fread(buf, 16, 1, fp);
    handle = init_etoken(buf, 16);
    iprint(DPI_DEBUG_MIDDLEBOX, "Handle", (handle->value), 0, (handle->len), (handle->len));
    add_handle_table_token(table, handle);
  }

  fclose(fp);
  free_handle_table(table);
  free_dpi_context(dpi);
  printf("finish verifying the file\n");

  return 0;
}
