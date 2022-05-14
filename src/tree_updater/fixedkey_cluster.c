#include <dpi/debug.h>
#include <dpi/defines.h>
#include "tree_updater.h"
#include <openssl/evp.h>

#include "../etc/pbytes.h"
#include "../etc/search_tree.h"
#include "../etc/handle_table.h"
#include "../etc/security_context.h"

int fixedkey_cluster_tree_update(dpi_t *dpi, etoken_t *etoken, int idx, int result, int cvalue)
{
	fstart("dpi: %p, etoken: %p, idx: %d, result: %d, cvalue: %d", dpi, etoken, idx, result, cvalue);
	assert(dpi != NULL);

	int i, j, rc, rs, ret, elen, hlen, bsize, num_of_clusters;
  uint8_t *hval;
  uint8_t tmp[16] = {0, };
  uint8_t eval[16] = {0, };
  uint8_t sbuf[16] = {0, };
  uint64_t salt;
  search_tree_t *tree, *newtree;
  handle_table_t *table;
  hbucket_t *bucket;
  hentry_t *entry;
  etoken_t *handle;
  security_context_t *context;
  EVP_CIPHER_CTX *ectx;

	ret = FALSE;

  tree = dpi_get_search_tree(dpi, idx);
  if (tree)
    free_search_tree(tree);
  context = dpi_get_security_context(dpi);

  table = dpi_get_handle_table(dpi);
  salt = get_context_salt(context);
  rs = get_context_rs_value(context);
  bsize = get_context_block_size(context);
  ectx = get_context_encryption_context(context);
  num_of_clusters = dpi_get_num_of_clusters(dpi);

  dmsg(DPI_DEBUG_MIDDLEBOX, "encrypted token is found");
  salt += cvalue;
  VAR_TO_PTR_8BYTES(salt, sbuf);
  newtree = init_search_tree();

  for (j=0; j<NUM_OF_BUCKETS; j++)
  {
    if (j % num_of_clusters != (idx % num_of_clusters))
      continue;
    bucket = table->buckets[j];
    entry = bucket->head;

    while (entry)
    {
      handle = entry->handle;
      hval = handle->value;

      for (i=0; i<bsize; i++)
        tmp[i] = hval[i] ^ sbuf[i];
      rc = EVP_EncryptUpdate(ectx, eval, &elen, tmp, bsize);
      assert(rc == 1);

      for (i=0; i<bsize; i++)
        eval[i] = eval[i] ^ hval[i];

      etoken = init_etoken(eval, rs);
  
      dprint(DPI_DEBUG_MIDDLEBOX, "Handle", hval, 0, hlen, 16);
      dprint(DPI_DEBUG_MIDDLEBOX, "Encrypted Token", eval, 0, rs, 16);

      newtree = insert_search_tree_token(newtree, handle, etoken);

      entry = entry->next;
    }
  }
  dpi_set_search_tree(dpi, idx, newtree);

	ffinish("ret: %d", ret);
	return ret;
}
