#include <dpi/debug.h>
#include <dpi/defines.h>
#include "tree_updater.h"
#include <openssl/evp.h>

#include "../etc/pbytes.h"
#include "../etc/search_tree.h"
#include "../etc/handle_table.h"
#include "../etc/security_context.h"

int nonfixedkey_perkeyword_tree_update(dpi_t *dpi, etoken_t *etoken, int idx, int result, int cvalue)
{
	fstart("dpi: %p, etoken: %p, idx: %d, result: %d, cvalue: %d", dpi, etoken, idx, result, cvalue);
	assert(dpi != NULL);

	int rc, rs, ret, elen, count, bsize;
  uint8_t eval[16] = {0, };
  uint8_t sbuf[16] = {0, };
  uint64_t salt;
  search_tree_t *tree;
  handle_table_t *table;
  etoken_t *handle, *uetoken;
  hentry_t *entry;
  security_context_t *context;
  EVP_CIPHER_CTX *ectx;
  const EVP_CIPHER *eevp;

  ret = FALSE;
  if (!result)
    goto out;

  table = dpi_get_handle_table(dpi);
  context = dpi_get_security_context(dpi);
  tree = dpi_get_search_tree(dpi, idx);

  salt = get_context_salt(context);
  rs = get_context_rs_value(context);
  bsize = get_context_block_size(context);

  dmsg(DPI_DEBUG_MIDDLEBOX, "encrypted token is found");
  handle = delete_search_tree_token(tree, etoken);

  dmsg(DPI_DEBUG_MIDDLEBOX, "the token deletion success");

  entry = find_handle_table_token(table, handle);
  assert(entry != NULL);
  dmsg(DPI_DEBUG_MIDDLEBOX, "before counter: %d", entry->count);
  entry->count++;
  dmsg(DPI_DEBUG_MIDDLEBOX, "after counter: %d", entry->count);
  count = entry->count;

  ectx = EVP_CIPHER_CTX_new();
  assert(ectx != NULL);
  eevp = get_context_cipher_algorithm(context);
  assert(eevp != NULL);
  rc = EVP_EncryptInit_ex(ectx, eevp, NULL, handle->value, NULL);
  assert(rc == 1);

  salt += count;
  VAR_TO_PTR_8BYTES(salt, sbuf);
  rc = EVP_EncryptUpdate(ectx, eval, &elen, sbuf, bsize);
  assert(rc == 1);

  EVP_CIPHER_CTX_free(ectx);
    
  uetoken = init_etoken(eval, rs);
  dprint(DPI_DEBUG_MIDDLEBOX, "updated token", (uetoken->value), 0, (uetoken->len), 16);
    
  tree = insert_search_tree_token(tree, handle, uetoken);

  // TODO: Do I need to set the new tree again?
  dpi_set_search_tree(dpi, 0, tree);
out:
	ffinish("ret: %d", ret);
	return ret;
}
