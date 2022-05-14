#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <dpi/debug.h>
#include <dpi/defines.h>
#include <dpi/association_table.h>
#include <openssl/ssl.h>

entry_t *init_association_entry(uint8_t *key, int klen);
void free_association_entry(entry_t *entry);
entry_t *insert_entry(association_table_t *table, uint8_t *key, int klen);
entry_t *find_entry(association_table_t *table, uint8_t *key, int klen);
entry_t *pop_entry(association_table_t *table);

association_table_t *init_association_table(conf_t *conf)
{
  fstart("conf: %p", conf);
  association_table_t *ret;

  ret = (association_table_t *)calloc(1, sizeof(association_table_t));
  if (!ret)
    goto err;
  ret->conf = conf;

  ffinish("ret: %p", ret);
  return ret;
err:
  ferr("error happended in initializing the association table");
  return NULL;
}

void free_association_table(association_table_t *table)
{
  fstart("table: %p", table);
  
  entry_t *tmp;
  if (table)
  {
    while (table->num > 0)
    {
      tmp = pop_entry(table);
      free_association_entry(tmp);
    }
  }

  ffinish();
}

dpi_t *get_associated_dpi_context(association_table_t *table, uint8_t *key, int klen)
{
  fstart("table: %p, key: %p, klen: %d", table, key, klen);
  assert(table != NULL);
  assert(key != NULL);
  assert(klen > 0);

  entry_t *tmp;
  dpi_t *ret;
  
  tmp = NULL;
  ret = NULL;

  tmp = find_entry(table, key, klen);
  if (tmp)
    ret = tmp->dpi;

  ffinish("ret: %p", ret);
  return ret;
}

entry_t *init_association_entry(uint8_t *key, int klen)
{
  fstart();

  entry_t *ret;
  ret = (entry_t *)calloc(1, sizeof(entry_t));
  memcpy(ret->key, key, klen);
  ret->klen = klen;

  ffinish("ret: %p", ret);
  return ret;
}

void free_association_entry(entry_t *entry)
{
  fstart("entry: %p", entry);
  
  if (entry)
  {
    if (entry->client)
      SSL_free(entry->client);

    if (entry->server)
      SSL_free(entry->server);

    free(entry);
  }

  ffinish();
}

int update_channel(association_table_t *table, uint8_t *key, int klen, SSL *ssl, 
    int server)
{
  fstart("table: %p, key: %p, klen: %d, ssl: %p, server: %d", table, key, klen, ssl, server);
  assert(table != NULL);
  assert(key != NULL);
  assert(klen > 0);
  assert(ssl != NULL);

  int ret;
  entry_t *entry;

  ret = SUCCESS;
  entry = find_entry(table, key, klen);
  if (!entry)
    entry = insert_entry(table, key, klen);

  if (server)
    entry->server = ssl;
  else
    entry->client = ssl;

  ffinish("ret: %d", ret);
  return ret;
}

entry_t *insert_entry(association_table_t *table, uint8_t *key, int klen)
{
  fstart("table: %p, key: %p, klen: %d", table, key, klen);
  assert(table != NULL);
  assert(key != NULL);
  assert(klen > 0);

  entry_t *ret, *entry, *tmp;
  ret = NULL;

  if (!find_entry(table, key, klen))
  {
    entry = init_association_entry(key, klen);
    tmp = table->head;
    table->head = entry;
    entry->next = tmp;
    if (entry->next)
      entry->next->prev = entry;
    table->num += 1;
    ret = entry;

    entry->dpi = init_dpi_context(DPI_ROLE_MIDDLEBOX, table->conf);
    dpi_rule_preparation(entry->dpi);
  }

  ffinish("ret: %p", ret);
  return ret;
}

entry_t *pop_entry(association_table_t *table)
{
  fstart("table: %p", table);
  assert(table != NULL);

  entry_t *ret;
  ret = table->head;

  if (ret)
  {
    table->head = ret->next;
    table->num--;
    assert(table->num >= 0);
  }

  ffinish("ret: %p", ret);
  return ret;
}

int delete_entry(association_table_t *table, uint8_t *key, int klen)
{
  fstart("table: %p, key: %p, klen: %d", table, key, klen);
  assert(table != NULL);
  assert(key != NULL);
  assert(klen > 0);

  int ret;
  entry_t *entry;

  ret = SUCCESS;
  entry = find_entry(table, key, klen);
  
  if (entry)
  {
    if (entry->prev)
      entry->prev->next = entry->next;
    else
      table->head = entry->next;
    free_association_entry(entry);
    table->num--;
    assert(table->num >= 0);
  }

  ffinish("ret: %d", ret);
  return 1;
}

entry_t *find_entry(association_table_t *table, uint8_t *key, int klen)
{
  fstart("table: %p, key: %p, klen: %d", table, key, klen);
  assert(table != NULL);
  assert(key != NULL);
  assert(klen > 0);

  entry_t *ret, *curr;

  ret = NULL;
  curr = table->head;

  while (curr)
  {
    if (klen == curr->klen 
        && !strncmp((const char *)key, (const char *)curr->key, klen))
    {
      ret = curr;
      break;
    }
    curr = curr->next;
  }

  ffinish("ret: %p", ret);
  return ret;
}

SSL *get_peer_ssl(association_table_t *table, uint8_t *key, int klen, SSL *mine)
{
  fstart("table: %p, key: %p, klen: %d, mine: %p", table, key, klen, mine);
  assert(table != NULL);
  assert(key != NULL);
  assert(klen > 0);

  SSL *ret;
  entry_t *entry;
  ret = NULL;

  if ((entry = find_entry(table, key, klen)))
  {
    if (SSL_mt_dpi_is_server(mine))
      ret = entry->client;
    else
      ret = entry->server;
  }

  ffinish("ret: %p", ret);
  return ret;
}
