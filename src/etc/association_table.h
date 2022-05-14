/**
 * @file table.h
 * @author Hyunwoo Lee
 * @date 1 May 2018
 * @brief The definition of functions to manage table.
 */

#ifndef __TABLE_H__
#define __TABLE_H__

#include <stdint.h>
#include <openssl/ssl.h>
#include <dpi/dpi.h>

#define MAX_ENTRIES 1000
#define MAX_NAME_LENGTH 256
#define KEY_LENGTH 32

typedef struct entry_st
{
  uint8_t key[KEY_LENGTH];
  int klen;
  dpi_t *dpi;
  SSL *client;
  SSL *server;
  struct entry_st *prev;
  struct entry_st *next;
} entry_t;

typedef struct association_table_st
{
  int num;
  entry_t *head;
  conf_t *conf;
} association_table_t;

association_table_t *init_association_table(conf_t *conf);
void free_association_table(association_table_t *table);
dpi_t *get_associated_dpi_context(association_table_t *table, uint8_t *key, int klen);

int update_channel(association_table_t *table, uint8_t *key, int klen, SSL *ssl, 
    int server);
SSL *get_peer_ssl(association_table_t *table, uint8_t *key, int klen, SSL *mine);

#endif /* __TABLE_H__ */
