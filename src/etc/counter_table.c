#include "counter_table.h"
#include "token.h"

#include <dpi/debug.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/sha.h>
#include <openssl/rand.h>
#include "../etc/security_context.h"

counter_table_t *init_counter_table(param_t *param)
{
  fstart("param: %p", param);
  assert(param != NULL);

  int i, num_of_clusters, num_of_entries;
  counter_table_t *ret;
  token_t *token;
  uint16_t wsize;
  int bsize;
  uint8_t *tmp;

  num_of_clusters = get_param_num_of_clusters(param);
  num_of_entries = get_param_prev_num_of_entries(param);
  wsize = param->wlen;
  // TODO: the following bsize should be checked. The value is manually assigned.
  bsize = 16;
  tmp = (uint8_t *)calloc(1, wsize);

  ret = (counter_table_t *)calloc(1, sizeof(counter_table_t));

  for (i=0; i<NUM_OF_BUCKETS; i++)
    ret->buckets[i] = (bucket_t *)calloc(1, sizeof(bucket_t));

  ret->num_of_fetched = (int *)calloc(num_of_clusters, sizeof(int));
  ret->cvalues = (int *)calloc(num_of_clusters, sizeof(int));

  for (i=0; i<num_of_entries; i++)
  {
    token = init_token();
    RAND_bytes(tmp, wsize);
    set_token_value(token, tmp, wsize, bsize);
    add_counter_table_token(ret, token);
  }

  ffinish("ret: %p", ret);
  return ret;
}

void set_counter_table(dpi_t *dpi)
{
  fstart("dpi: %p", dpi);
  assert(dpi != NULL);

  FILE *fp;
  const char *rname;
  char *line;
  uint16_t wsize;
  size_t len;
  ssize_t read;
  int bsize;
  param_t *param;
  token_t *token;
  counter_table_t *table;
  security_context_t *context;

  line = NULL;
  param = dpi_get_params(dpi);
  table = dpi_get_counter_table(dpi);
  context = dpi_get_security_context(dpi);
  rname = param->rname;
  wsize = param->wlen;
  bsize = get_context_block_size(context);
  dmsg(DPI_DEBUG_MIDDLEBOX, "rname: %s, wsize: %u, bsize: %d", rname, wsize, bsize);

  fp = fopen(rname, "r");
  if (!fp) goto out;

  while ((read = getline(&line, &len, fp)) != -1)
  {
    token = init_token();
    set_token_value(token, (uint8_t *)line, wsize, bsize);
    add_counter_table_token(table, token);
    dmsg(DPI_DEBUG_MIDDLEBOX, "Keyword (%zu bytes) (entries: %d): %s", len, table->num_of_entries, line);

    if (line)
    {
      free(line);
      line = NULL;
    }
  }
   
  fclose(fp);

out:
  ffinish();
}

entry_t *find_counter_table_token(counter_table_t *table, token_t *token)
{
  fstart("table: %p, token: %p", table, token);
  assert(table != NULL);
  assert(token != NULL);

  entry_t *ret;
  unsigned int idx;
  entry_t *entry;

  ret = NULL;
  idx = token_hash(token) % NUM_OF_BUCKETS;
  entry = table->buckets[idx]->head;

  while (entry)
  {
    if (!strncmp((const char *)dpi_get_token_value(entry->token), 
          (const char *)dpi_get_token_value(token), dpi_get_token_length(token)))
    {
      ret = entry;
      break;
    }
    entry = entry->next;
  }

  ffinish("ret: %p", ret);
  return ret;
}

entry_t *add_counter_table_token(counter_table_t *table, token_t *token)
{
  fstart("table: %p, token: %p", table, token);
  assert(table != NULL);
  assert(token != NULL);
  
  unsigned int idx;
  entry_t *entry, *head;

  entry = find_counter_table_token(table, token);

  if (!entry)
  {
    entry = init_entry(token);
    idx = token_hash(token) % NUM_OF_BUCKETS;
    head = table->buckets[idx]->head;
    entry->next = head;
    table->buckets[idx]->head = entry;
    table->num_of_entries++;
  }

  ffinish();
  return entry;
}

int check_counter_table_num_of_fetched(counter_table_t *table, int idx, 
    int max_num_of_fetched)
{
  fstart("table: %p, idx: %d, max_num_of_fetched: %d", table, idx, max_num_of_fetched);

  int ret;
  ret = FALSE;
  
  if (table->num_of_fetched[idx] >= max_num_of_fetched)
  {
    table->cvalues[idx]++;
    table->num_of_fetched[idx] = 0;
  }

  ffinish("ret: %d", ret);
  return ret;
}

int get_counter_table_cvalue(counter_table_t *table, int cid)
{
  fstart("table: %p", table);

  int ret;
  ret = table->cvalues[cid];
  table->num_of_fetched[cid]++;

  ffinish("ret: %d", ret);
  return ret;
}

void free_counter_table(counter_table_t *table)
{
  fstart("table: %p", table);
  assert(table != NULL);

  int i;
  entry_t *curr, *next;
  bucket_t *bucket;

  if (table)
  {
    for (i=0; i<NUM_OF_BUCKETS; i++)
    {
      bucket = table->buckets[i];
      if (bucket)
      {
        curr = bucket->head;
        while (curr)
        {
          next = curr->next;
          if (curr->token)
            free_token(curr->token);
          free(curr);
          curr = next;
        }
      }
      free(bucket);
    }
    free(table);
  }

  ffinish();
}
