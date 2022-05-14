#ifndef __HANDLE_TABLE_H__
#define __HANDLE_TABLE_H__

#include <dpi/dpi_types.h>
#include <dpi/dpi.h>
#include <dpi/setting.h>
#include "table.h"

struct handle_table_st
{
  int gcount;
  int num_of_entries;
  hbucket_t *buckets[NUM_OF_BUCKETS];
};

handle_table_t *init_handle_table(void);
void set_handle_table(dpi_t *dpi);
hentry_t *add_handle_table_token(handle_table_t *table, etoken_t *handle);
hentry_t *find_handle_table_token(handle_table_t *table, etoken_t *handle);
void add_handle_table_gcount(handle_table_t *table);
int get_handle_table_gcount(handle_table_t *table);
void free_handle_table(handle_table_t *table);
#endif /* __HANDLE_TABLE_H__ */
