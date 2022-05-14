#ifndef __SEARCH_TREE_H__
#define __SEARCH_TREE_H__

#include <dpi/dpi_types.h>
#include <dpi/dpi.h>
#include <dpi/setting.h>

#include "token.h"
#include "../tree_updater/tree_updater.h"

typedef struct node_st
{
  etoken_t *handle;   // AES_k(r)
  etoken_t *etoken;   // AES_{AES_k(r)}(salt + ct_r)
  struct node_st *left;
  struct node_st *right;
  int height;
} node_t;

struct search_tree_st
{
  node_t *root;
  int count;
  int num_of_fetched;
  int success;
};

node_t *init_node(etoken_t *handle, etoken_t *etoken);
void free_node(node_t *node);

search_tree_t *init_search_tree(void);
void free_search_tree(search_tree_t *tree);

void traverse_search_tree(node_t *root);
void add_search_tree_num_of_fetched(search_tree_t *tree);
int find_search_tree_token(search_tree_t *tree, etoken_t *etoken, int *count);
search_tree_t *insert_search_tree_token(search_tree_t *tree, etoken_t *handle, etoken_t *etoken);
etoken_t *delete_search_tree_token(search_tree_t *tree, etoken_t *etoken);

void *tree_manager_loop(void *data);
void *tree_updater_loop(void *data);

node_t *rotate_search_tree_left(node_t *root);
node_t *rotate_search_tree_right(node_t *root);
#endif /* __SEARCH_TREE_H__ */
