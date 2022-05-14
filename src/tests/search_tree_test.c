#include "../etc/search_tree.h"
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#define TEST_FILE "../../data/test_1000.txt"
#define TEST_STRING_1 "Request."
#define TEST_STRING_2 "ricsson."

int main(int argc, char *argv[])
{
  search_tree_t *tree;
  etoken_t *etoken, *handle;
  uint8_t *val;
  int ret, count;

  tree = init_search_tree();

  printf("\n>> Insert c\n");
  val = (uint8_t *)calloc(5, sizeof(uint8_t));
  memcpy(val, "ccccc", 5);
  handle = init_etoken(val, 5);
  etoken = init_etoken(val, 5);
  free(val);
  tree = insert_search_tree_token(tree, handle, etoken);
  traverse_search_tree(tree->root);

  printf("\n>> Insert a\n");
  val = (uint8_t *)calloc(5, sizeof(uint8_t));
  memcpy(val, "aaaaa", 5);
  handle = init_etoken(val, 5);
  etoken = init_etoken(val, 5);
  tree = insert_search_tree_token(tree, handle, etoken);
  traverse_search_tree(tree->root);

  printf("\n>> Insert b\n");
  val = (uint8_t *)calloc(5, sizeof(uint8_t));
  memcpy(val, "bbbbb", 5);
  handle = init_etoken(val, 5);
  etoken = init_etoken(val, 5);
  tree = insert_search_tree_token(tree, handle, etoken);
  traverse_search_tree(tree->root);

  printf("\n>> Search e\n");
  val = (uint8_t *)calloc(5, sizeof(uint8_t));
  memcpy(val, "eeeee", 5);
  handle = init_etoken(val, 5);
  etoken = init_etoken(val, 5);
  count = 0;
  ret = find_search_tree_token(tree, etoken, &count);
  if (ret)
    printf("token is in the tree\n");
  else
    printf("token is not in the tree\n");

  printf("\n>> Insert e\n");
  tree = insert_search_tree_token(tree, handle, etoken);
  traverse_search_tree(tree->root);
  ret = find_search_tree_token(tree, etoken, &count);
  if (ret)
    printf("token is in the tree\n");
  else
    printf("token is not in the tree\n");

  printf("\n>> Insert d\n");
  val = (uint8_t *)calloc(5, sizeof(uint8_t));
  memcpy(val, "ddddd", 5);
  handle = init_etoken(val, 5);
  etoken = init_etoken(val, 5);
  tree = insert_search_tree_token(tree, handle, etoken);
  traverse_search_tree(tree->root);

  printf("\n>> Delete b\n");
  val = (uint8_t *)calloc(5, sizeof(uint8_t));
  memcpy(val, "bbbbb", 5);
  handle = init_etoken(val, 5);
  etoken = init_etoken(val, 5);
  handle = delete_search_tree_token(tree, etoken);
  if (handle)
    printf("token deletion succeed\n");
  else
    printf("token deletion failed\n");
  free_etoken(etoken);
  traverse_search_tree(tree->root);

  printf("\n>> Delete a\n");
  val = (uint8_t *)calloc(5, sizeof(uint8_t));
  memcpy(val, "aaaaa", 5);
  etoken = init_etoken(val, 5);
  handle = delete_search_tree_token(tree, etoken);
  if (handle)
    printf("token deletion succeed\n");
  else
    printf("token deletion failed\n");
  free_etoken(etoken);
  traverse_search_tree(tree->root);

  printf("\n>> Delete e\n");
  val = (uint8_t *)calloc(5, sizeof(uint8_t));
  memcpy(val, "eeeee", 5);
  etoken = init_etoken(val, 5);
  handle = delete_search_tree_token(tree, etoken);
  if (handle)
    printf("token deletion succeed\n");
  else
    printf("token deletion failed\n");
  free_etoken(etoken);
  traverse_search_tree(tree->root);

  printf("\n>> Delete c\n");
  val = (uint8_t *)calloc(5, sizeof(uint8_t));
  memcpy(val, "ccccc", 5);
  etoken = init_etoken(val, 5);
  handle = delete_search_tree_token(tree, etoken);
  if (handle)
    printf("token deletion succeed\n");
  else
    printf("token deletion failed\n");
  free_etoken(etoken);
  traverse_search_tree(tree->root);

  printf("\n>> Delete d\n");
  val = (uint8_t *)calloc(5, sizeof(uint8_t));
  memcpy(val, "ddddd", 5);
  etoken = init_etoken(val, 5);
  handle = delete_search_tree_token(tree, etoken);
  if (handle)
    printf("token deletion succeed\n");
  else
    printf("token deletion failed\n");
  free_etoken(etoken);
  traverse_search_tree(tree->root);

  free_search_tree(tree);
  return 0;
}
