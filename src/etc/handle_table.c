#include "handle_table.h"
#include "token.h"
#include "security_context.h"

#include <dpi/debug.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/sha.h>
#include <openssl/evp.h>

handle_table_t *init_handle_table(void)
{
  fstart();

  int i;
  handle_table_t *ret;

  ret = (handle_table_t *)calloc(1, sizeof(handle_table_t));

  for (i=0; i<NUM_OF_BUCKETS; i++)
    ret->buckets[i] = (hbucket_t *)calloc(1, sizeof(bucket_t));

  ffinish("ret: %p", ret);
  return ret;
}

hentry_t *find_handle_table_token(handle_table_t *table, etoken_t *handle)
{
  fstart("table: %p, handle: %p", table, handle);
  assert(table != NULL);
  assert(handle != NULL);

  hentry_t *ret;
  unsigned int idx;
  hentry_t *entry;

  ret = NULL;
  idx = etoken_hash(handle) % NUM_OF_BUCKETS;

  entry = table->buckets[idx]->head;

  while (entry)
  {
    //printf("entry->handle: %p (%d bytes), handle: %p (%d bytes)\n",
    //    entry->handle, dpi_get_encrypted_token_length(entry->handle),
    //    handle, dpi_get_encrypted_token_length(handle));
    if (!strncmp((const char *)(entry->handle->value), 
          (const char *)(handle->value), 
          dpi_get_encrypted_token_length(handle)))
    {
      ret = entry;
      break;
    }
    entry = entry->next;
  }

  ffinish("ret: %p", ret);
  return ret;
}

hentry_t *add_handle_table_token(handle_table_t *table, etoken_t *handle)
{
  fstart("table: %p, handle: %p", table, handle);
  assert(table != NULL);
  assert(handle != NULL);
  
  unsigned int idx;
  hentry_t *entry, *head;

  entry = find_handle_table_token(table, handle);

  if (!entry)
  {
    entry = init_hentry(handle);
    idx = etoken_hash(handle) % NUM_OF_BUCKETS;
    head = table->buckets[idx]->head;
    entry->next = head;
    table->buckets[idx]->head = entry;
    table->buckets[idx]->num++;
    table->num_of_entries++;
  }

  ffinish();
  return entry;
}

void add_handle_table_gcount(handle_table_t *table)
{
  fstart("table: %p", table);

  table->gcount++;

  ffinish();
}

int get_handle_table_gcount(handle_table_t *table)
{
  fstart("table: %p", table);

  int ret;
  ret = table->gcount;

  ffinish("ret: %d", ret);
  return ret;
}

void free_handle_table(handle_table_t *table)
{
  fstart("table: %p", table);
  assert(table != NULL);

  int i;
  hentry_t *curr, *next;
  hbucket_t *bucket;

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
          if (curr->handle)
            free_etoken(curr->handle);
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
