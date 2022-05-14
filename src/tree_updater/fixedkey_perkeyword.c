#include <dpi/debug.h>
#include <dpi/defines.h>
#include "tree_updater.h"
#include <openssl/evp.h>

#include "../etc/pbytes.h"
#include "../etc/search_tree.h"
#include "../etc/handle_table.h"
#include "../etc/security_context.h"

int fixedkey_perkeyword_tree_update(dpi_t *dpi, etoken_t *etoken, int idx, int result, int cvalue)
{
	fstart("dpi: %p, etoken: %p, idx: %d, result: %d, cvalue: %d", dpi, etoken, idx, result, cvalue);
	assert(dpi != NULL);

	int i, rc, rs, ret, elen, count, bsize;
  uint8_t *hval;
  uint8_t eval[16] = {0, };
  uint8_t sbuf[16] = {0, };
  uint8_t tmp[16] = {0, };
  uint64_t salt;
  search_tree_t *tree;
  handle_table_t *table;
  etoken_t *handle, *uetoken;
  hentry_t *entry;
  security_context_t *context;
  EVP_CIPHER_CTX *ectx;

	ret = FALSE;
  if (!result)
    goto out;

  table = dpi_get_handle_table(dpi);
  context = dpi_get_security_context(dpi);
  tree = dpi_get_search_tree(dpi, idx);

  ectx = get_context_encryption_context(context);
  salt = get_context_salt(context);
  rs = get_context_rs_value(context);
  bsize = get_context_block_size(context);

  dmsg(DPI_DEBUG_MIDDLEBOX, "encrypted token is found");
  handle = delete_search_tree_token(tree, etoken);

  if (handle)
  {
    dmsg(DPI_DEBUG_MIDDLEBOX, "the token deletion success");
  }
  else
  {
    dmsg(DPI_DEBUG_MIDDLEBOX, "the token deletion failure");
  }

  entry = find_handle_table_token(table, handle);
  assert(entry != NULL);
  dmsg(DPI_DEBUG_MIDDLEBOX, "before counter: %d", entry->count);
  entry->count++;
  dmsg(DPI_DEBUG_MIDDLEBOX, "after counter: %d", entry->count);
  count = entry->count;

  salt += count;
  VAR_TO_PTR_8BYTES(salt, sbuf);
  hval = handle->value;
  for (i=0; i<bsize; i++)
    tmp[i] = hval[i] ^ sbuf[i];
  rc = EVP_EncryptUpdate(ectx, eval, &elen, tmp, bsize);
  assert(rc == 1);

  for (i=0; i<bsize; i++)
    eval[i] = eval[i] ^ hval[i];

  uetoken = init_etoken(eval, rs);
  tree = insert_search_tree_token(tree, handle, uetoken);
out:
	ffinish("ret: %d", ret);
	return ret;
}
