#include <dpi/debug.h>
#include <dpi/defines.h>
#include "token_detector.h"
#include <openssl/evp.h>

#include "../etc/pbytes.h"
#include "../etc/search_tree.h"
#include "../etc/handle_table.h"
#include "../etc/security_context.h"

#ifdef INTERNAL
  #define print_interval(m, a, b) \
    printf("%s: %lu ns\n", m, b - a);
#else
  #define print_interval(m, a, b)
#endif /* INTERNAL */

#ifdef INTERNAL
unsigned long get_current_clock_time_dfp(void)
{
  struct timespec ts;
  clock_gettime(CLOCK_MONOTONIC, &ts);
  return ts.tv_sec * 1000000000 + ts.tv_nsec;
}
#endif /* INTERNAL */

int fixedkey_perkeyword_token_detection(dpi_t *dpi, etoken_t *etoken)
{
	fstart("dpi: %p, etoken: %p", dpi, etoken);
	assert(dpi != NULL);
	assert(etoken != NULL);

	int ret, count;
  search_tree_t *tree;
#ifdef INTERNAL
  unsigned long start[10], end[10], tstart, tend;
  int idx = 0;
#endif /* INTERNAL */
  ret = 0;

#ifdef INTERNAL
  tstart = start[idx] = get_current_clock_time_dfp();
#endif /* INTERNAL */
  ret = FALSE;
  tree = dpi_get_current_search_tree(dpi, 0);
#ifdef INTERNAL
  end[idx++] = get_current_clock_time_dfp();
#endif /* INTERNAL */

  if (!tree) goto out;

#ifdef INTERNAL
  start[idx] = get_current_clock_time_dfp();
#endif /* INTERNAL */
  count = 0;
  ret = find_search_tree_token(tree, etoken, &count);
#ifdef INTERNAL
  end[idx++] = get_current_clock_time_dfp();
#endif /* INTERNAL */

#ifdef INTERNAL
  start[idx] = get_current_clock_time_dfp();
#endif /* INTERNAL */
  add_search_tree_num_of_fetched(tree);
#ifdef INTERNAL
  end[idx++] = get_current_clock_time_dfp();
#endif /* INTERNAL */

#ifdef INTERNAL
  start[idx] = get_current_clock_time_dfp();
#endif /* INTERNAL */
  dpi_update_current_search_tree(dpi, 0, etoken, ret);
#ifdef INTERNAL
  tend = end[idx++] = get_current_clock_time_dfp();
#endif /* INTERNAL */

  print_interval("others 1", start[0], end[0]);
  //printf("count: %d\n", count);
  print_interval("search", start[1], end[1]);
  print_interval("others 2", start[2], end[2]);
  print_interval("update", start[3], end[3]);
  print_interval("total", tstart, tend);

out:
	ffinish("ret: %d", ret);
	return ret;
}
