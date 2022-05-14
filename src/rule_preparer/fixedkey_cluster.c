#include <dpi/debug.h>
#include <dpi/defines.h>
#include <openssl/evp.h>
#include <stdlib.h>
#include <time.h>

#include "rule_preparer.h"
#include "../etc/handle_table.h"
#include "../etc/security_context.h"
#include "../etc/search_tree.h"
#include "../etc/pbytes.h"

int fixedkey_cluster_rule_preparation(dpi_t *dpi)
{
	fstart("dpi: %p", dpi);
	assert(dpi != NULL);

	int ret;
  FILE *fp;
  const char *rname;
  char *line;
  int i, idx, rc, rs, hlen, sklen, elen, bsize, num_of_clusters;
  int *cvalues;
  uint8_t tmp[16] = {0, };
  uint8_t hval[16] = {0, };
  uint8_t eval[16] = {0, };
  uint8_t sbuf[16] = {0, };
  uint8_t *skey;
  uint16_t wsize;
  uint64_t salt;
  size_t len;
  ssize_t read;
  param_t *param;
  token_t *rule;
  etoken_t *handle, *etoken;
  security_context_t *context;
  search_tree_t **tree;
  handle_table_t *table;
  EVP_CIPHER_CTX *ectx;
  const EVP_CIPHER *eevp;

	ret = FAILURE;
  line = NULL;
  param = dpi_get_params(dpi);
  table = dpi_get_handle_table(dpi);
  context = dpi_get_security_context(dpi);
  cvalues = dpi_get_search_tree_cvalues(dpi);
  num_of_clusters = dpi_get_num_of_clusters(dpi);
  tree = (search_tree_t **)calloc(num_of_clusters, sizeof(search_tree_t *));
  rname = param->rname;
  wsize = param->wlen;
  dmsg(DPI_DEBUG_MIDDLEBOX, "rname: %s, wsize: %u", rname, wsize);

  fp = fopen(rname, "r");
  if (!fp) goto out;

  ectx = get_context_encryption_context(context);
  assert(ectx != NULL);
  eevp = get_context_cipher_algorithm(context);
  assert(eevp != NULL);
  skey = get_context_secret(context, &sklen);
  assert(skey != NULL);
  salt = get_context_salt(context);
  VAR_TO_PTR_8BYTES(salt, sbuf);
  rs = get_context_rs_value(context);
  assert(rs > 0);
  bsize = get_context_block_size(context);

  if (!dpi_get_is_using_tree_updater(dpi))
  {
    for (idx=0; idx<num_of_clusters; idx++)
      tree[idx] = init_search_tree();
  }

  while ((read = getline(&line, &len, fp)) != -1)
  {
    rule = init_token();
    set_token_value(rule, (uint8_t *)line, wsize, bsize);

    // Generate a handle
    dmsg(DPI_DEBUG_MIDDLEBOX, "Rule (%d bytes): %s", (rule->len), (rule->value));

    // AES(k ^ m) ^ (k ^ m)
    for (i=0; i<bsize; i++)
      tmp[i] = (rule->value)[i] ^ skey[i];
    rc = EVP_EncryptUpdate(ectx, hval, &hlen, tmp, bsize);
    assert(rc == 1);

    // tmp -> skey
    for (i=0; i<bsize; i++)
      hval[i] = hval[i] ^ skey[i];
  
    handle = init_etoken(hval, hlen);
    add_handle_table_token(table, handle);

    //if (dpi_get_is_using_tree_updater(dpi))
    //{
    //  add_handle_table_token(table, handle);
    //}
    //else
    if (!dpi_get_is_using_tree_updater(dpi))
    {
      idx = hval[0] % num_of_clusters;
      for (i=0; i<bsize; i++)
        tmp[i] = hval[i] ^ sbuf[i];
      rc = EVP_EncryptUpdate(ectx, eval, &elen, tmp, bsize);
      assert(rc == 1);

      // tmp -> hval
      for (i=0; i<bsize; i++)
        eval[i] = eval[i] ^ hval[i];

      etoken = init_etoken(eval, rs);

      dprint(DPI_DEBUG_MIDDLEBOX, "Handle", hval, 0, hlen, 16);
      dprint(DPI_DEBUG_MIDDLEBOX, "Encrypted Token", eval, 0, rs, 16);

      tree[idx] = insert_search_tree_token(tree[idx], handle, etoken);
    }

    if (line)
    {
      free(line);
      line = NULL;
    }
  }

  fclose(fp);

  if (!dpi_get_is_using_tree_updater(dpi))
  {
    for (idx=0; idx<num_of_clusters; idx++)
    {
      dpi_set_search_tree(dpi, idx, tree[idx]);
      cvalues[idx] = 0;
    }
  }
  else
    dpi_set_rule_is_ready(dpi);

  ret = SUCCESS;

out:
	ffinish("ret: %d", ret);
	return ret;
}
