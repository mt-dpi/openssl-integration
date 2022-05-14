#include <dpi/debug.h>
#include <dpi/defines.h>
#include "tree_updater.h"
#include <openssl/evp.h>

#include "../etc/pbytes.h"
#include "../etc/search_tree.h"
#include "../etc/handle_table.h"
#include "../etc/security_context.h"

int nonfixedkey_global_tree_update(dpi_t *dpi, etoken_t *etoken, int idx, int result, int cvalue)
{
	fstart("dpi: %p, etoken: %p, idx: %d, result: %d, cvalue: %d", dpi, etoken, idx, result, cvalue);
	assert(dpi != NULL);

	int i, rc, rs, ret, elen, bsize;
  uint8_t eval[16] = {0, };
  uint8_t sbuf[16] = {0, };
  uint64_t salt;
  search_tree_t *tree, *newtree;
  handle_table_t *table;
  hbucket_t *bucket;
  hentry_t *entry;
  etoken_t *handle, *uetoken;
  security_context_t *context;
  EVP_CIPHER_CTX *ectx;
  const EVP_CIPHER *eevp;

	ret = FALSE;

  tree = dpi_get_search_tree(dpi, idx);
  if (tree)
    free_search_tree(tree);
  context = dpi_get_security_context(dpi);

  table = dpi_get_handle_table(dpi);
  salt = get_context_salt(context);
  rs = get_context_rs_value(context);
  bsize = get_context_block_size(context);

  salt += cvalue;
  VAR_TO_PTR_8BYTES(salt, sbuf);
  newtree = init_search_tree();

  for (i=0; i<NUM_OF_BUCKETS; i++)
  {
    bucket = table->buckets[i];
    entry = bucket->head;

    while (entry)
    {
      handle = entry->handle;

      ectx = EVP_CIPHER_CTX_new();
      assert(ectx != NULL);
      eevp = get_context_cipher_algorithm(context);
      assert(eevp != NULL);
      rc = EVP_EncryptInit_ex(ectx, eevp, NULL, handle->value, NULL);
      assert(rc == 1);

      rc = EVP_EncryptUpdate(ectx, eval, &elen, sbuf, bsize);
      assert(rc == 1);
      EVP_CIPHER_CTX_free(ectx);
    
      uetoken = init_etoken(eval, rs);
      newtree = insert_search_tree_token(newtree, handle, uetoken);

      entry = entry->next;
    }
  }
  dpi_set_search_tree(dpi, idx, newtree);

	ffinish("ret: %d", ret);
	return ret;
}
