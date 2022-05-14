#include <dpi/debug.h>
#include <dpi/defines.h>
#include "token_detector.h"
#include <openssl/evp.h>

#include "../etc/search_tree.h"

#ifdef INTERNAL
  #define print_interval(m, a, b) \
    printf("%s: %lu ns\n", m, b - a);
#else
  #define print_interval(m, a, b)
#endif /* INTERNAL */

#ifdef INTERNAL
unsigned long get_current_clock_time_dfg(void)
{
  struct timespec ts;
  clock_gettime(CLOCK_MONOTONIC, &ts);
  return ts.tv_sec * 1000000000 + ts.tv_nsec;
}
#endif /* INTERNAL */

int fixedkey_global_token_detection(dpi_t *dpi, etoken_t *etoken)
{
	fstart("dpi: %p, etoken: %p", dpi, etoken);
	assert(dpi != NULL);
	assert(etoken != NULL);

	int ret, idx, num_of_clusters, num_of_trees, max_num_of_fetched, cvalue, count;
  int *active, *cvalues;
  search_tree_t *tree;
#ifdef INTERNAL
  unsigned long start[10], end[10], tstart, tend;
  int i = 0;
#endif /* INTERNAL */

#ifdef INTERNAL
  tstart = start[i] = get_current_clock_time_dfg();
#endif /* INTERNAL */
	ret = FALSE;
  tree = dpi_get_current_search_tree(dpi, 0);
  active = dpi_get_search_tree_activeness(dpi);
  cvalues = dpi_get_search_tree_cvalues(dpi);
  idx = dpi_get_current_search_tree_idx(dpi, 0);
  num_of_clusters = dpi_get_num_of_clusters(dpi);
  num_of_trees = dpi_get_num_of_trees(dpi);
  max_num_of_fetched = dpi_get_max_num_of_fetched(dpi);
#ifdef INTERNAL
  end[i++] = get_current_clock_time_dfg();
#endif /* INTERNAL */

  // Search the encrypted token from the search tree
#ifdef INTERNAL
  start[i] = get_current_clock_time_dfg();
#endif /* INTERNAL */
  count = 0;
  ret = find_search_tree_token(tree, etoken, &count);
#ifdef INTERNAL
  end[i++] = get_current_clock_time_dfg();
#endif /* INTERNAL */
  add_search_tree_num_of_fetched(tree);
  if (tree->num_of_fetched >= max_num_of_fetched)
  {
    if (!dpi_get_is_using_tree_updater(dpi))
    {
      cvalue = cvalues[0] + 1;
#ifdef INTERNAL
      start[i] = get_current_clock_time_dfg();
#endif /* INTERNAL */
      dpi_update_search_tree(dpi, 0, -1, cvalue);
#ifdef INTERNAL
      end[i++] = get_current_clock_time_dfg();
#endif /* INTERNAL */
      cvalues[0] = cvalue;
    }
    else
    {
      active[idx] = 0;
      idx = (idx + num_of_clusters) % num_of_trees;
      dpi_set_current_search_tree_idx(dpi, 0, idx);
    }
  }

#ifdef INTERNAL
  tend = get_current_clock_time_dfg();
#endif /* INTERNAL */
  print_interval("others 1", start[0], end[0]);
  print_interval("search", start[1], end[1]);
  //printf("count: %d\n", count);
#ifdef INTERNAL
  if (i > 2)
#endif /* INTERNAL */
    print_interval("update", start[2], end[2]);
  print_interval("total", tstart, tend);

	ffinish("ret: %d", ret);
	return ret;
}
