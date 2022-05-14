#include "search_tree.h"
#include "token.h"
#include <dpi/debug.h>
#include <dpi/broker.h>

#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#ifdef INTERNAL
  #define print_interval(m, a, b) \
    printf("%s: %lu ns\n", m, b - a);
#else
  #define print_interval(m, a, b)
#endif /* INTERNAL */

#ifdef INTERNAL
unsigned long get_current_clock_time_st(void)
{
  struct timespec ts;
  clock_gettime(CLOCK_MONOTONIC, &ts);
  return ts.tv_sec * 1000000000 + ts.tv_nsec;
}
#endif /* INTERNAL */

node_t *init_node(etoken_t *handle, etoken_t *etoken)
{
  fstart("etoken: %p", etoken);

  node_t *ret;
  ret = (node_t *)calloc(1, sizeof(node_t));
  ret->handle = handle;
  ret->etoken = etoken;
  ret->height = 1;

  ffinish("ret: %p", ret);
  return ret;
}

void free_node(node_t *node)
{
  fstart("node: %p", node);

  if (node)
  {
    if (node->etoken)
      free_etoken(node->etoken);
    free(node);
  }

  ffinish();
}

int get_node_height(node_t *node)
{
  fstart("node: %p", node);

  int ret;

  ret = 0;
  if (node)
    ret = node->height;

  ffinish("ret: %d", ret);
  return ret;
}

int get_node_balance(node_t *node)
{
  fstart("node: %p", node);

  int lh, rh, ret;
  lh = get_node_height(node->left);
  rh = get_node_height(node->right);
  ret = lh - rh;

  ffinish("ret: %d", ret);
  return ret;
}

void update_node_height(node_t *node)
{
  fstart("node: %p", node);

  int lh, rh;
  lh = get_node_height(node->left);
  rh = get_node_height(node->right);

  if (lh > rh)
    node->height = lh + 1;
  else
    node->height = rh + 1;

  ffinish();
}

void traverse_search_tree(node_t *root)
{
  fstart("root: %p", root);

  uint8_t *p;
  int len;

  if (root)
  {
    if (root->left)
    {
      dmsg(DPI_DEBUG_MIDDLEBOX, "traverse: root->left");
      traverse_search_tree(root->left);
    }
    p = root->etoken->value;
    len = root->etoken->len;
    iprint(DPI_DEBUG_MIDDLEBOX, "eToken", p, 0, len, 16);
    if (root->right)
    {
      dmsg(DPI_DEBUG_MIDDLEBOX, "traverse: root->right");
      traverse_search_tree(root->right);
    }
  }
}

int search_node(search_tree_t *tree, node_t *root, etoken_t *etoken, int *count)
{
  fstart("tree: %p, root: %p, etoken: %p, count: %p", tree, root, etoken, count);
  assert(tree != NULL);
  assert(etoken != NULL);

  int ret, compare;
  unsigned long start, end;

  ret = FALSE;
  (*count)++;

  if (root)
  {
    dprint(DPI_DEBUG_MIDDLEBOX, "search key", (etoken->value), 0, (etoken->len), 16);
    dprint(DPI_DEBUG_MIDDLEBOX, "etoken value", (root->etoken->value), 0, (root->etoken->len), 16);
#ifdef INTERNAL
    //start = get_current_clock_time_st();
#endif /* INTERNAL */
    //printf("etoken->value (%d bytes): %02x %02x %02x %02x %02x\n", etoken->len, etoken->value[0], etoken->value[1], etoken->value[2], etoken->value[3], etoken->value[4]);
    //printf("root->etoken->value (%d bytes): %02x %02x %02x %02x %02x\n", root->etoken->len, root->etoken->value[0], root->etoken->value[1], root->etoken->value[2], root->etoken->value[3], root->etoken->value[4]);
    compare = strncmp((const char *)etoken->value, (const char *)root->etoken->value, root->etoken->len);
#ifdef INTERNAL
    //end = get_current_clock_time_st();
#endif /* INTERNAL */
    //printf("compare: %d\n", compare);
    //print_interval("strncmp", start, end);

    if (compare < 0)
      ret = search_node(tree, root->left, etoken, count);
    else if (compare > 0)
      ret = search_node(tree, root->right, etoken, count);
    else
      ret = TRUE;
  }

  ffinish("ret: %d", ret);
  return ret;
}

void add_search_tree_num_of_fetched(search_tree_t *tree)
{
  fstart("tree: %p", tree);
  assert(tree != NULL);

  tree->num_of_fetched++;

  ffinish();
}

int find_search_tree_token(search_tree_t *tree, etoken_t *token, int *count)
{
  fstart("tree: %p, token: %p, count: %p", tree, token, count);
  assert(tree != NULL);
  assert(token != NULL);

  int ret;
  ret = FALSE;

  if (tree->root)
    ret = search_node(tree, tree->root, token, count);

  ffinish("ret: %d", ret);
  return ret;
}

node_t *balancing_insert_search_tree(search_tree_t *tree, node_t *root, etoken_t *etoken)
{
  fstart("tree: %p, root: %p, etoken: %p", tree, root, etoken);
  assert(tree != NULL);
  assert(root != NULL);
  assert(etoken != NULL);

  node_t *ret;
  int compare, compare_with_left, compare_with_right, balance;

  ret = NULL;
  compare_with_left = 0;
  compare_with_right = 0;
  balance = get_node_balance(root);

  dprint(DPI_DEBUG_MIDDLEBOX, "tree->root", (tree->root->etoken->value), 0, (tree->root->etoken->len), 16);
  dprint(DPI_DEBUG_MIDDLEBOX, "node", (root->etoken->value), 0, (root->etoken->len), 16);
  if (root->left)
  {
    dprint(DPI_DEBUG_MIDDLEBOX, "node->left", (root->left->etoken->value), 0, (root->left->etoken->len), 16);
  }

  if (root->right)
  {
    dprint(DPI_DEBUG_MIDDLEBOX, "node->right", (root->right->etoken->value), 0, (root->right->etoken->len), 16);
  }
  
  compare = strncmp((const char *)etoken->value, 
      (const char *)root->etoken->value, root->etoken->len);

  if (balance > 1)
  {
    compare_with_left = strncmp((const char *)etoken->value, 
      (const char *)root->left->etoken->value, root->left->etoken->len);
    if (compare > 0 || compare_with_left < 0)
    {
      dmsg(DPI_DEBUG_MIDDLEBOX, "balance > 1 and compare with left < 0");
      root = rotate_search_tree_right(root);
    }
    else if (compare_with_left > 0)
    {
      dmsg(DPI_DEBUG_MIDDLEBOX, "balance > 1 and compare with left > 0");
      root->left = rotate_search_tree_left(root->left);
      dprint(DPI_DEBUG_MIDDLEBOX, "node before rotate right", (root->etoken->value), 0, (root->etoken->len), 16);
      root = rotate_search_tree_right(root);
      dprint(DPI_DEBUG_MIDDLEBOX, "node after rotate right", (root->etoken->value), 0, (root->etoken->len), 16);
      if (root->left)
      {
        dprint(DPI_DEBUG_MIDDLEBOX, "node->left", (root->left->etoken->value), 0, (root->left->etoken->len), 16);
      }

      if (root->right)
      {
        dprint(DPI_DEBUG_MIDDLEBOX, "node->right", (root->right->etoken->value), 0, (root->right->etoken->len), 16);
      }
    }
  }
  else if (balance < -1)
  {
    compare_with_right = strncmp((const char *)etoken->value, 
      (const char *)root->right->etoken->value, root->right->etoken->len);

    if (compare < 0 || compare_with_right > 0)
    {
      dmsg(DPI_DEBUG_MIDDLEBOX, "balance < -1 and compare with right > 0");
      root = rotate_search_tree_left(root);
    }
    else if (compare_with_right < 0)
    {
      dmsg(DPI_DEBUG_MIDDLEBOX, "balance < -1 and compare with right < 0");
      root->right = rotate_search_tree_right(root->right);
      root = rotate_search_tree_left(root);
    }
  }

  ret = root;
  ffinish("ret: %p", ret);
  return ret;
}

node_t *balancing_delete_search_tree(search_tree_t *tree, node_t *root, etoken_t *etoken)
{
  fstart("tree: %p, root: %p, etoken: %p", tree, root, etoken);
  assert(tree != NULL);
  assert(root != NULL);
  assert(etoken != NULL);

  node_t *ret;
  int compare, compare_with_left, compare_with_right, balance;

  ret = NULL;
  compare_with_left = 0;
  compare_with_right = 0;
  balance = get_node_balance(root);

  dprint(DPI_DEBUG_MIDDLEBOX, "tree->root", (tree->root->etoken->value), 0, (tree->root->etoken->len), 16);
  dprint(DPI_DEBUG_MIDDLEBOX, "node", (root->etoken->value), 0, (root->etoken->len), 16);
  if (root->left)
  {
    dprint(DPI_DEBUG_MIDDLEBOX, "node->left", (root->left->etoken->value), 0, (root->left->etoken->len), 16);
  }

  if (root->right)
  {
    dprint(DPI_DEBUG_MIDDLEBOX, "node->right", (root->right->etoken->value), 0, (root->right->etoken->len), 16);
  }
  
  compare = strncmp((const char *)etoken->value, 
      (const char *)root->etoken->value, root->etoken->len);

  if (balance > 1)
  {
    compare_with_left = strncmp((const char *)etoken->value, 
      (const char *)root->left->etoken->value, root->left->etoken->len);
    if (compare > 0)
    {
      dmsg(DPI_DEBUG_MIDDLEBOX, "compare > 0");
      root = rotate_search_tree_right(root);
    }
    else if (compare_with_left < 0) // LR
    {
      dmsg(DPI_DEBUG_MIDDLEBOX, "balance > 1 and compare with left < 0");
      root->left = rotate_search_tree_left(root->left);
      dprint(DPI_DEBUG_MIDDLEBOX, "node before rotate right", (root->etoken->value), 0, (root->etoken->len), 16);
      root = rotate_search_tree_right(root);
      dprint(DPI_DEBUG_MIDDLEBOX, "node after rotate right", (root->etoken->value), 0, (root->etoken->len), 16);
      if (root->left)
      {
        dprint(DPI_DEBUG_MIDDLEBOX, "node->left", (root->left->etoken->value), 0, (root->left->etoken->len), 16);
      }

      if (root->right)
      {
        dprint(DPI_DEBUG_MIDDLEBOX, "node->right", (root->right->etoken->value), 0, (root->right->etoken->len), 16);
      }
    }
    else if (compare_with_left > 0) // LL
    {
      dmsg(DPI_DEBUG_MIDDLEBOX, "balance > 1 and compare with left > 0");
      dprint(DPI_DEBUG_MIDDLEBOX, "node before rotate right", (root->etoken->value), 0, (root->etoken->len), 16);
      root = rotate_search_tree_right(root);
      dprint(DPI_DEBUG_MIDDLEBOX, "node after rotate right", (root->etoken->value), 0, (root->etoken->len), 16);
      if (root->left)
      {
        dprint(DPI_DEBUG_MIDDLEBOX, "node->left", (root->left->etoken->value), 0, (root->left->etoken->len), 16);
      }

      if (root->right)
      {
        dprint(DPI_DEBUG_MIDDLEBOX, "node->right", (root->right->etoken->value), 0, (root->right->etoken->len), 16);
      }
    }
  }
  else if (balance < -1)
  {
    compare_with_right = strncmp((const char *)etoken->value, 
      (const char *)root->right->etoken->value, root->right->etoken->len);

    if (compare < 0)
    {
      dmsg(DPI_DEBUG_MIDDLEBOX, "balance < -1 and compare with right > 0");
      root = rotate_search_tree_left(root);
    }
    else if (compare_with_right < 0) // RR
    {
      dmsg(DPI_DEBUG_MIDDLEBOX, "balance < -1 and compare with right > 0");
      root = rotate_search_tree_left(root);
    }
    else if (compare_with_right > 0) // RL
    {
      dmsg(DPI_DEBUG_MIDDLEBOX, "balance < -1 and compare with right > 0");
      root->right = rotate_search_tree_right(root->right);
      root = rotate_search_tree_left(root);
    }
  }

  ret = root;
  ffinish("ret: %p", ret);
  return ret;
}

int transplant_node(search_tree_t *tree, node_t **x)
{
  fstart("tree: %p, x: %p", tree, x);
  assert(tree != NULL);
  assert(x != NULL);

  int ret;
  node_t *y, *z, *pz;

  ret = TRUE;
  y = *x;

  if (!((*x)->left))
  {
    *x = (*x)->right;
  }
  else if (!((*x)->right))
  {
    *x = (*x)->left;
  }
  else
  {
    z = (*x)->right;
    pz = (*x);

    while (z->left)
    {
      pz = z;
      z = z->left;
    }

//    free_etoken(x->etoken);
    (*x)->etoken = z->etoken;
    (*x)->handle = z->handle;

    if (pz == (*x))
    {
      (*x)->right = z->right;
    }
    else
    {
      pz->left = z->right;
    }

    y = z;
    ret = FALSE;
  }

//  if (y == z)
//    free(y);
//  else
//    free_node(y);
  ffinish("ret: %d", ret);
  return ret;
}

node_t *insert_node(search_tree_t *tree, node_t *root, node_t *item)
{
  fstart("tree: %p, node: %p, item: %p", tree, root, item);
  assert(tree != NULL);
  assert(item != NULL);

  node_t *ret;
  int compare;

  if (!root)
  {
    root = item;
    ret = root;
    tree->success = TRUE;
    goto out;
  }

  compare = strncmp((const char *)root->etoken->value, 
      (const char *)item->etoken->value, item->etoken->len);

  if (compare < 0)
  {
    dmsg(DPI_DEBUG_MIDDLEBOX, "insert to right");
    root->right = insert_node(tree, root->right, item);

    // Inserted for BST
    ret = root;
  }
  else if (compare > 0)
  {
    dmsg(DPI_DEBUG_MIDDLEBOX, "insert to left");
    root->left = insert_node(tree, root->left, item);

    // Inserted for BST
    ret = root;
  }
  else
  {
    ret = root;
    goto out;
  }

  // Comment Out for BST
  //update_node_height(root);
  //ret = balancing_insert_search_tree(tree, root, item->etoken);

out:
  ffinish("ret: %p", ret);
  return ret;
}

search_tree_t *insert_search_tree_token(search_tree_t *tree, etoken_t *handle, 
    etoken_t *etoken)
{
  fstart("tree: %p, handle: %p, token: %p", tree, handle, etoken);
  assert(tree != NULL);
  assert(handle != NULL);
  assert(etoken != NULL);

  search_tree_t *ret;
  node_t *node;
  int found;
  ret = tree;

  dprint(DPI_DEBUG_MIDDLEBOX, "Insert node", (etoken->value), 0, (etoken->len), 16);

  //found = _find_search_tree_token(tree, etoken);
  found = FALSE;
  if (!found)
  {
    node = init_node(handle, etoken);
    tree->success = FALSE;
    ret->root = insert_node(tree, ret->root, node);
    if (tree->success)
      tree->count++;
    dmsg(DPI_DEBUG_MIDDLEBOX, "Total %d token inserted", tree->count);
  }

  ffinish("ret: %p", ret);
  return ret;
}

node_t *delete_node(search_tree_t *tree, node_t *node, etoken_t *etoken, 
    etoken_t **handle)
{
  fstart("tree: %p, node: %p, etoken: %p, handle: %p", tree, node, etoken, handle);
  assert(tree != NULL);
  assert(etoken != NULL);
  assert(handle != NULL);

  node_t *ret, *tmp;
  int compare, node_deleted;

  ret = NULL;

  if (!node) goto out;

  dprint(DPI_DEBUG_MIDDLEBOX, "node value", (node->etoken->value), 0, (node->etoken->len), 16);
  dprint(DPI_DEBUG_MIDDLEBOX, "key value", (etoken->value), 0, (etoken->len), 16);
  compare = strncmp((const char *)node->etoken->value, (const char *)etoken->value, 
      node->etoken->len);
  node_deleted = FALSE;

  if (compare > 0)
    node->left = delete_node(tree, node->left, etoken, handle);
  else if (compare < 0)
    node->right = delete_node(tree, node->right, etoken, handle);
  else if (compare == 0)
  {
    *handle = node->handle;
    tree->success = TRUE;

    dprint(DPI_DEBUG_MIDDLEBOX, "Handle found", ((*handle)->value), 0, ((*handle)->len), 16);
    //dmsg(DPI_DEBUG_MIDDLEBOX, "transplant before node: %p", node);
    // Comment out for BST
    node_deleted = transplant_node(tree, &node);
    //dmsg(DPI_DEBUG_MIDDLEBOX, "transplant after node: %p", node);
  }

  ret = node;
  // Comment out for BST
  //if (!node_deleted)
  //{
  //  update_node_height(node);
  //  ret = balancing_delete_search_tree(tree, node, etoken);
  //}

out:
  ffinish("ret: %p", ret);
  return ret;
}

etoken_t *delete_search_tree_token(search_tree_t *tree, etoken_t *etoken)
{
  fstart("tree: %p, etoken: %p", tree, etoken);
  assert(tree != NULL);
  assert(etoken != NULL);

  etoken_t *ret;
  int found, count;

  ret = NULL;

  dprint(DPI_DEBUG_MIDDLEBOX, "Delete node", (etoken->value), 0, (etoken->len), 16);

  count = 0;
  tree->success = FALSE;
  tree->root = delete_node(tree, tree->root, etoken, &ret);
  if (tree->success)
    tree->count--;
  dmsg(DPI_DEBUG_MIDDLEBOX, "Total %d tokens left", tree->count);

  ffinish("ret: %p", ret);
  return ret;
}

node_t *rotate_search_tree_left(node_t *root)
{
  fstart("root: %p", root);
  assert(root != NULL);

  dmsg(DPI_DEBUG_MIDDLEBOX, "rotate left");
  node_t *ret;

  dmsg(DPI_DEBUG_MIDDLEBOX, "rotate_search_tree_left\n");
  ret = root->right;
  root->right = ret->left;
  ret->left = root;

  update_node_height(root);
  update_node_height(ret);

  ffinish("ret: %p", ret);
  return ret;
}

node_t *rotate_search_tree_right(node_t *root)
{
  fstart("root: %p", root);
  assert(root != NULL);

  dmsg(DPI_DEBUG_MIDDLEBOX, "rotate right: root->left: %p, root->right: %p", root->left, root->right);
  node_t *ret;

  dmsg(DPI_DEBUG_MIDDLEBOX, "rotate_search_tree_right\n");
  ret = root->left;
  root->left = ret->right;
  ret->right = root;

  update_node_height(root);
  update_node_height(ret);

  ffinish("ret: %p", ret);
  return ret;
}

/*
void *tree_manager_loop(void *data)
{
  dpi_t *dpi;
  request_t *req;
  response_t *resp;
  broker_t *broker;
  search_tree_t *tree;
  int id, result, num_of_trees, num_of_clusters, max_num_of_fetched, idx;
  int *active;

  dpi = (dpi_t *)data;
  broker = dpi_get_broker(dpi);
  active = dpi_get_search_tree_activeness(dpi);
  num_of_trees = dpi_get_num_of_trees(dpi);
  num_of_clusters = dpi_get_num_of_clusters(dpi);
  max_num_of_fetched = dpi_get_max_num_of_fetched(dpi);

  while (dpi_get_running(dpi))
  {
    if ((req = get_request_from_queue(broker)))
    {
      switch (req->op)
      {
        case BROKER_OP_INSERT_NODE:
          idx = dpi_get_current_search_tree_idx(dpi);
          tree = dpi_get_current_search_tree(dpi);
          if (!tree)
          {
            tree = init_search_tree();
            dpi_set_search_tree(dpi, idx, tree);
          }
          insert_search_tree_token(tree, req->handle, req->etoken);
          break;
        case BROKER_OP_DELETE_NODE:
          tree = dpi_get_current_search_tree(dpi);
          delete_search_tree_token(tree, req->etoken);
          break;
        case BROKER_OP_SEARCH_NODE:
          idx = dpi_get_current_search_tree_idx(dpi);
          tree = dpi_get_current_search_tree(dpi);
          result = find_search_tree_token(tree, req->etoken);
          id = get_request_id(req);
          resp = init_response(id, result);
          if (dpi_get_num_of_trees(dpi) == 1)
            dpi_update_current_search_tree(dpi, req->etoken, result);
          add_response_to_queue(broker, resp);
          if (num_of_trees > 1 && tree->num_of_fetched > max_num_of_fetched)
          {
            active[idx] = 0;
            idx = (idx + num_of_clusters) % num_of_trees;
            dpi_set_current_search_tree_idx(dpi, idx);
          }
          break;
        case BROKER_OP_ACTIVE_TREE:
          break;
      }
    }
  }

  return NULL;
}
*/

void *tree_updater_loop(void *data)
{
  dpi_t *dpi;
  int i, num_of_trees, num_of_clusters, cid, cvalue;
  int *active;
  int *cvalues;

  dpi = (dpi_t *)data;

  num_of_trees = dpi_get_num_of_trees(dpi);
  num_of_clusters = dpi_get_num_of_clusters(dpi);
  active = dpi_get_search_tree_activeness(dpi);
  cvalues = dpi_get_search_tree_cvalues(dpi);

  while (!dpi_get_rule_is_ready(dpi)) {}

  while (dpi_get_running(dpi))
  {
    for (i=0; i<num_of_trees; i++)
    {
      if (active[i] == 0)
      {
        cid = i % num_of_clusters;
        cvalue = cvalues[cid];
        dpi_update_search_tree(dpi, i, -1, cvalue + 1);
        cvalues[cid] = cvalue + 1;
        active[i] = 1;
      }
    }
  }

  return NULL;
}

search_tree_t *init_search_tree(void)
{
  fstart();

  search_tree_t *ret;
  ret = (search_tree_t *)calloc(1, sizeof(search_tree_t));

  ffinish("ret: %p", ret);
  return ret;
}

void free_search_tree(search_tree_t *tree)
{
  fstart("tree: %p", tree);

  if (tree)
  {
    while (tree->root)
    {
      delete_search_tree_token(tree, tree->root->etoken);
    }
    free(tree);
  }

  ffinish();
}

