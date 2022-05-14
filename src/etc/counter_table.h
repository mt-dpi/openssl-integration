#ifndef __COUNTER_TABLE_H__
#define __COUNTER_TABLE_H__

#include <dpi/dpi_types.h>
#include <dpi/dpi.h>
#include <dpi/setting.h>
#include "table.h"

struct counter_table_st
{
  int num_of_entries;
  int *num_of_fetched;
  int *cvalues;
  bucket_t *buckets[NUM_OF_BUCKETS];
};

counter_table_t *init_counter_table(param_t *param);
void set_counter_table(dpi_t *dpi);
entry_t *add_counter_table_token(counter_table_t *table, token_t *token);
entry_t *find_counter_table_token(counter_table_t *table, token_t *token);
int check_counter_table_num_of_fetched(counter_table_t *table, int idx, 
    int max_num_of_fetched);
int get_counter_table_cvalue(counter_table_t *table, int cid);
void free_counter_table(counter_table_t *table);
#endif /* __COUNTER_TABLE_H__ */
