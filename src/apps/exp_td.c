#include <stdlib.h>
#include <stdio.h>
#include <getopt.h>
#include <string.h>
#include <unistd.h>
#include <dpi/dpi.h>
#include <dpi/debug.h>
#include "../etc/token.h"
#include "../etc/search_tree.h"
#include "../etc/pbytes.h"
#include "../etc/security_context.h"
#include "../etc/handle_table.h"

#define COUNT 100000
#define COUNTD 100000.0

#define print_interval(m, a, b) \
  printf("%s: %lu ns\n", m, b - a);

#define print_per_interval(m, a, b) \
  printf("%s: %.2f ns\n", m, (b - a)/COUNTD);

#ifndef BLKSIZE
#define BLKSIZE 16
#endif /* BLKSIZE */

static inline void memxor(uint8_t dst[BLKSIZE], const uint8_t *a, const uint8_t *b)
{
  uint64_t *s = (uint64_t *)(dst);
  const uint64_t *au = (const uint64_t *)(a);
  const uint64_t *bu = (const uint64_t *)(b);

  s[0] = au[0] ^ bu[0];
  s[1] = au[1] ^ bu[1];
}

unsigned long get_current_time(void)
{
  struct timespec ts;
  clock_gettime(CLOCK_MONOTONIC, &ts);
  return ts.tv_sec * 1000000000 + ts.tv_nsec;
}

int main(int argc, char *argv[])
{
  dpi_t *dpi;
  conf_t *conf;
  uint8_t *buf;
  int ret, fsize, i, count, rc, rs, bsize, elen;
  token_t *token;
  etoken_t *etoken, *uetoken, *handle;
  FILE *fp;
  const char *iname;
  unsigned long start, end;
  double val1, val2;
  search_tree_t *tree;
  handle_table_t *table;
  security_context_t *context;
  EVP_CIPHER_CTX *ectx;
  const EVP_CIPHER *eevp;
  uint8_t sbuf[16] = {0, };
  uint8_t eval[16] = {0, };
  uint8_t tmp[16] = {0, };
  uint8_t *hval;
  uint64_t salt;
  hentry_t *entry;

  conf = init_conf_module();
  set_conf_module(conf, argc, argv);
  dpi = init_dpi_context(DPI_ROLE_MIDDLEBOX, conf);
  free_conf_module(conf);
  dpi_rule_preparation(dpi);
  sleep(1);

  iname = dpi_get_input_filename(dpi);
  fp = fopen(iname, "r");
  if (fp)
  {
    fseek(fp, 0, SEEK_END);
    fsize = ftell(fp);
    rewind(fp);

    buf = (uint8_t *)malloc(fsize);
    if (!buf)
    {
      printf("error> out of memory\n");
      return 1;
    }
    fread(buf, 1, fsize, fp);

    fclose(fp);
  }
  else
  {
    emsg("error> file open error\n");
    return 1;
  }

  dpi_add_message(dpi, buf, fsize);

  // Fixed detection (found)
  token = dpi_get_next_token(dpi);
  if (token)
  {
    start = get_current_time();
    etoken = dpi_token_encryption(dpi, token);
    iprint(DPI_DEBUG_MIDDLEBOX, "etoken", (etoken->value), 0, (etoken->len), 16);
    printf("Fixed key detection (line-by-line) (found)\n");
    start = get_current_time();
    for (i=0; i<COUNT; i++)
      tree = dpi_get_current_search_tree(dpi, 0);
    end = get_current_time();
    print_per_interval("Time: tree = dpi_get_current_search_tree(dpi, 0);", start, end);

    start = get_current_time();
    for (i=0; i<COUNT; i++)
      count = 0;
    end = get_current_time();
    print_per_interval("Time: count = 0;", start, end);

    start = get_current_time();
    for (i=0; i<COUNT; i++)
      ret = find_search_tree_token(tree, etoken, &count);
    end = get_current_time();
    print_per_interval("Time: ret = find_search_tree_token(tree, etoken, &count);", start, end);

    start = get_current_time();
    for (i=0; i<COUNT; i++)
      add_search_tree_num_of_fetched(tree);
    end = get_current_time();
    print_per_interval("Time: add_search_tree_num_of_fetched(tree);", start, end);

    printf("ret: %d\n", ret);
    if (ret)
    {
      start = get_current_time();
      for (i=0; i<COUNT; i++)
        table = dpi_get_handle_table(dpi);
      end = get_current_time();
      print_per_interval("Time: table = dpi_get_handle_table(dpi);", start, end);

      start = get_current_time();
      for (i=0; i<COUNT; i++)
        context = dpi_get_security_context(dpi);
      end = get_current_time();
      print_per_interval("Time: context = dpi_get_security_context(dpi);", start, end);

      start = get_current_time();
      for (i=0; i<COUNT; i++)
        ectx = get_context_encryption_context(context);
      end = get_current_time();
      print_per_interval("Time: ectx = get_context_encryption_context(context);", start, end);

      start = get_current_time();
      for (i=0; i<COUNT; i++)
        salt = get_context_salt(context);
      end = get_current_time();
      print_per_interval("Time: salt = get_context_salt(context);", start, end);

      start = get_current_time();
      for (i=0; i<COUNT; i++)
        rs = get_context_rs_value(context);
      end = get_current_time();
      print_per_interval("Time: rs = get_context_rs_value(context)", start, end);

      start = get_current_time();
      for (i=0; i<COUNT; i++)
        bsize = get_context_block_size(context);
      end = get_current_time();
      print_per_interval("Time: bsize = get_context_block_size(context);", start, end);

      start = get_current_time();
      handle = delete_search_tree_token(tree, etoken);
      end = get_current_time();
      print_per_interval("Time: handle = delete_search_tree_token(tree, etoken);", start, end);

      start = get_current_time();
      for (i=0; i<COUNT; i++)
        entry = find_handle_table_token(table, handle);
      end = get_current_time();
      print_per_interval("Time: table = dpi_get_handle_table(dpi);", start, end);

      // Commented out for the experiment
      /*
      start = get_current_time();
      for (i=0; i<COUNT; i++)
        entry->count++;
      end = get_current_time();
      print_per_interval("Time: entry->count++;", start, end);
      */

      start = get_current_time();
      for (i=0; i<COUNT; i++)
        count = entry->count;
      end = get_current_time();
      print_per_interval("Time: count = entry->count;", start, end);

      start = get_current_time();
      for (i=0; i<COUNT; i++)
        salt += count;
      end = get_current_time();
      print_per_interval("Time: salt += count;", start, end);

      start = get_current_time();
      for (i=0; i<COUNT; i++)
        VAR_TO_PTR_8BYTES(salt, sbuf);
      end = get_current_time();
      print_per_interval("Time: VAR_TO_PTR_8BYTES(salt, sbuf);", start, end);

      start = get_current_time();
      for (i=0; i<COUNT; i++)
        hval = handle->value;
      end = get_current_time();
      print_per_interval("Time: hval = handle->value;", start, end);

      start = get_current_time();
      for (i=0; i<COUNT; i++)
        memxor(tmp, hval, sbuf);
      end = get_current_time();
      print_per_interval("Time: memxor(tmp, hval, sbuf);", start, end);

      start = get_current_time();
      for (i=0; i<COUNT; i++)
        rc = EVP_EncryptUpdate(ectx, eval, &elen, tmp, bsize);
      end = get_current_time();
      print_per_interval("Time: rc = EVP_EncryptUpdate(ectx, eval, &elen, tmp, bsize);", start, end);

      start = get_current_time();
      for (i=0; i<COUNT; i++)
        memxor(eval, eval, hval);
      end = get_current_time();
      print_per_interval("Time: memxor(eval, eval, hval);", start, end);

      start = get_current_time();
      for (i=0; i<COUNT; i++)
        uetoken = init_etoken(eval, rs);
      end = get_current_time();
      print_per_interval("Time: uetoken = init_etoken(eval, rs);", start, end);

      start = get_current_time();
      for (i=0; i<COUNT; i++)
        tree = insert_search_tree_token(tree, handle, uetoken);
      end = get_current_time();
      print_per_interval("Time: tree = insert_search_tree_token(tree, handle, uetoken);", start, end);

      imsg(DPI_DEBUG_MIDDLEBOX, "Result: Found");
      printf("Result: Found\n");
    }
    else
    {
      imsg(DPI_DEBUG_MIDDLEBOX, "Result: Not Found");
      printf("Result: Not Found\n");
    }
  }

  // Non-fixed key detection (found)
  token = dpi_get_next_token(dpi);
  if (token)
  {
    start = get_current_time();
    etoken = dpi_token_encryption(dpi, token);
    iprint(DPI_DEBUG_MIDDLEBOX, "etoken", (etoken->value), 0, (etoken->len), 16);
    printf("Non-fixed key detection (line-by-line) (found)\n");
    start = get_current_time();
    for (i=0; i<COUNT; i++)
      tree = dpi_get_current_search_tree(dpi, 0);
    end = get_current_time();
    print_per_interval("Time: tree = dpi_get_current_search_tree(dpi, 0);", start, end);

    start = get_current_time();
    for (i=0; i<COUNT; i++)
      count = 0;
    end = get_current_time();
    print_per_interval("Time: count = 0;", start, end);

    start = get_current_time();
    for (i=0; i<COUNT; i++)
      ret = find_search_tree_token(tree, etoken, &count);
    end = get_current_time();
    print_per_interval("Time: ret = find_search_tree_token(tree, etoken, &count);", start, end);

    start = get_current_time();
    for (i=0; i<COUNT; i++)
      add_search_tree_num_of_fetched(tree);
    end = get_current_time();
    print_per_interval("Time: add_search_tree_num_of_fetched(tree);", start, end);

    printf("ret: %d\n", ret);
    if (ret)
    {
      start = get_current_time();
      for (i=0; i<COUNT; i++)
        table = dpi_get_handle_table(dpi);
      end = get_current_time();
      print_per_interval("Time: table = dpi_get_handle_table(dpi);", start, end);

      start = get_current_time();
      for (i=0; i<COUNT; i++)
        context = dpi_get_security_context(dpi);
      end = get_current_time();
      print_per_interval("Time: context = dpi_get_security_context(dpi);", start, end);

      start = get_current_time();
      for (i=0; i<COUNT; i++)
        salt = get_context_salt(context);
      end = get_current_time();
      print_per_interval("Time: salt = get_context_salt(context);", start, end);

      start = get_current_time();
      for (i=0; i<COUNT; i++)
        rs = get_context_rs_value(context);
      end = get_current_time();
      print_per_interval("Time: rs = get_context_rs_value(context)", start, end);

      start = get_current_time();
      for (i=0; i<COUNT; i++)
        bsize = get_context_block_size(context);
      end = get_current_time();
      print_per_interval("Time: bsize = get_context_block_size(context);", start, end);

      start = get_current_time();
      handle = delete_search_tree_token(tree, etoken);
      end = get_current_time();
      print_per_interval("Time: handle = delete_search_tree_token(tree, etoken);", start, end);

      start = get_current_time();
      for (i=0; i<COUNT; i++)
        entry = find_handle_table_token(table, handle);
      end = get_current_time();
      print_per_interval("Time: table = dpi_get_handle_table(dpi);", start, end);

      // Commented out for the experiment
      /*
      start = get_current_time();
      for (i=0; i<COUNT; i++)
        entry->count++;
      end = get_current_time();
      print_per_interval("Time: entry->count++;", start, end);
      */

      start = get_current_time();
      for (i=0; i<COUNT; i++)
        count = entry->count;
      end = get_current_time();
      print_per_interval("Time: count = entry->count;", start, end);

      start = get_current_time();
      for (i=0; i<COUNT; i++)
        ectx = EVP_CIPHER_CTX_new();
      end = get_current_time();
      print_per_interval("Time: ectx = EVP_CIPHER_CTX_new();", start, end);

      start = get_current_time();
      for (i=0; i<COUNT; i++)
        eevp = get_context_cipher_algorithm(context);
      end = get_current_time();
      print_per_interval("Time: eevp = get_context_cipher_algorithm(context);", start, end);

      start = get_current_time();
      for (i=0; i<COUNT; i++)
        rc = EVP_EncryptInit_ex(ectx, eevp, NULL, handle->value, NULL);
      end = get_current_time();
      print_per_interval("Time: rc = EVP_EncryptInit_ex(ectx, eevp, NULL, handle->value, NULL);", start, end);

      start = get_current_time();
      for (i=0; i<COUNT; i++)
        salt += count;
      end = get_current_time();
      print_per_interval("Time: salt += count;", start, end);

      start = get_current_time();
      for (i=0; i<COUNT; i++)
        VAR_TO_PTR_8BYTES(salt, sbuf);
      end = get_current_time();
      print_per_interval("Time: VAR_TO_PTR_8BYTES(salt, sbuf);", start, end);

      start = get_current_time();
      for (i=0; i<COUNT; i++)
        rc = EVP_EncryptUpdate(ectx, eval, &elen, sbuf, bsize);
      end = get_current_time();
      print_per_interval("Time: rc = EVP_EncryptUpdate(ectx, eval, &elen, sbuf, bsize);", start, end);

      start = get_current_time();
      EVP_CIPHER_CTX_free(ectx);
      end = get_current_time();
      print_per_interval("Time: EVP_CIPHER_CTX_free(ectx);", start, end);

      start = get_current_time();
      for (i=0; i<COUNT; i++)
        uetoken = init_etoken(eval, rs);
      end = get_current_time();
      print_per_interval("Time: uetoken = init_etoken(eval, rs);", start, end);

      start = get_current_time();
      for (i=0; i<COUNT; i++)
        tree = insert_search_tree_token(tree, handle, uetoken);
      end = get_current_time();
      print_per_interval("Time: tree = insert_search_tree_token(tree, handle, uetoken);", start, end);

      imsg(DPI_DEBUG_MIDDLEBOX, "Result: Found");
      printf("Result: Found\n");
    }
    else
    {
      imsg(DPI_DEBUG_MIDDLEBOX, "Result: Not Found");
      printf("Result: Not Found\n");
    }

    /*
    start = get_current_time();
    for (i=0; i<COUNT; i++)
      dpi_token_encryption(dpi, token);
    end = get_current_time();
    val2 = (end - start) / COUNTD;
    printf("Averaged elapsed time (found) (token_encryption): %.2lf ns\n", val2);
    printf("Averaged elapsed time (found) (token_detection): %.2lf ns\n", val1 - val2);
    */
  }
  
  // Fixed key detection (not found)
  token = dpi_get_next_token(dpi);
  if (token)
  {
    start = get_current_time();
    etoken = dpi_token_encryption(dpi, token);
    iprint(DPI_DEBUG_MIDDLEBOX, "etoken", (etoken->value), 0, (etoken->len), 16);
    printf("Fixed key detection (line-by-line) (not found)\n");
    start = get_current_time();
    for (i=0; i<COUNT; i++)
      tree = dpi_get_current_search_tree(dpi, 0);
    end = get_current_time();
    print_per_interval("Time: tree = dpi_get_current_search_tree(dpi, 0);", start, end);

    start = get_current_time();
    for (i=0; i<COUNT; i++)
      count = 0;
    end = get_current_time();
    print_per_interval("Time: count = 0;", start, end);

    start = get_current_time();
    for (i=0; i<COUNT; i++)
      ret = find_search_tree_token(tree, etoken, &count);
    end = get_current_time();
    print_per_interval("Time: ret = find_search_tree_token(tree, etoken, &count);", start, end);

    start = get_current_time();
    for (i=0; i<COUNT; i++)
      add_search_tree_num_of_fetched(tree);
    end = get_current_time();
    print_per_interval("Time: add_search_tree_num_of_fetched(tree);", start, end);

    printf("ret: %d\n", ret);
    if (ret)
    {
      start = get_current_time();
      for (i=0; i<COUNT; i++)
        table = dpi_get_handle_table(dpi);
      end = get_current_time();
      print_per_interval("Time: table = dpi_get_handle_table(dpi);", start, end);

      start = get_current_time();
      for (i=0; i<COUNT; i++)
        context = dpi_get_security_context(dpi);
      end = get_current_time();
      print_per_interval("Time: context = dpi_get_security_context(dpi);", start, end);

      start = get_current_time();
      for (i=0; i<COUNT; i++)
        ectx = get_context_encryption_context(context);
      end = get_current_time();
      print_per_interval("Time: ectx = get_context_encryption_context(context);", start, end);

      start = get_current_time();
      for (i=0; i<COUNT; i++)
        salt = get_context_salt(context);
      end = get_current_time();
      print_per_interval("Time: salt = get_context_salt(context);", start, end);

      start = get_current_time();
      for (i=0; i<COUNT; i++)
        rs = get_context_rs_value(context);
      end = get_current_time();
      print_per_interval("Time: rs = get_context_rs_value(context)", start, end);

      start = get_current_time();
      for (i=0; i<COUNT; i++)
        bsize = get_context_block_size(context);
      end = get_current_time();
      print_per_interval("Time: bsize = get_context_block_size(context);", start, end);

      start = get_current_time();
      handle = delete_search_tree_token(tree, etoken);
      end = get_current_time();
      print_per_interval("Time: handle = delete_search_tree_token(tree, etoken);", start, end);

      printf("table: %p, handle: %p\n", table, handle);
      start = get_current_time();
      for (i=0; i<COUNT; i++)
        entry = find_handle_table_token(table, handle);
      end = get_current_time();
      print_per_interval("Time: table = dpi_get_handle_table(dpi);", start, end);

      // Commented out for the experiment
      /*
      start = get_current_time();
      for (i=0; i<COUNT; i++)
        entry->count++;
      end = get_current_time();
      print_per_interval("Time: entry->count++;", start, end);
      */

      start = get_current_time();
      for (i=0; i<COUNT; i++)
        count = entry->count;
      end = get_current_time();
      print_per_interval("Time: count = entry->count;", start, end);

      start = get_current_time();
      for (i=0; i<COUNT; i++)
        salt += count;
      end = get_current_time();
      print_per_interval("Time: salt += count;", start, end);

      start = get_current_time();
      for (i=0; i<COUNT; i++)
        VAR_TO_PTR_8BYTES(salt, sbuf);
      end = get_current_time();
      print_per_interval("Time: VAR_TO_PTR_8BYTES(salt, sbuf);", start, end);

      start = get_current_time();
      for (i=0; i<COUNT; i++)
        hval = handle->value;
      end = get_current_time();
      print_per_interval("Time: hval = handle->value;", start, end);

      start = get_current_time();
      for (i=0; i<COUNT; i++)
        memxor(tmp, hval, sbuf);
      end = get_current_time();
      print_per_interval("Time: memxor(tmp, hval, sbuf);", start, end);

      start = get_current_time();
      for (i=0; i<COUNT; i++)
        rc = EVP_EncryptUpdate(ectx, eval, &elen, tmp, bsize);
      end = get_current_time();
      print_per_interval("Time: rc = EVP_EncryptUpdate(ectx, eval, &elen, tmp, bsize);", start, end);

      start = get_current_time();
      for (i=0; i<COUNT; i++)
        memxor(eval, eval, hval);
      end = get_current_time();
      print_per_interval("Time: memxor(eval, eval, hval);", start, end);

      start = get_current_time();
      for (i=0; i<COUNT; i++)
        uetoken = init_etoken(eval, rs);
      end = get_current_time();
      print_per_interval("Time: uetoken = init_etoken(eval, rs);", start, end);

      start = get_current_time();
      for (i=0; i<COUNT; i++)
        tree = insert_search_tree_token(tree, handle, uetoken);
      end = get_current_time();
      print_per_interval("Time: tree = insert_search_tree_token(tree, handle, uetoken);", start, end);

      imsg(DPI_DEBUG_MIDDLEBOX, "Result: Found");
      printf("Result: Found\n");
    }
    else
    {
      imsg(DPI_DEBUG_MIDDLEBOX, "Result: Not Found");
      printf("Result: Not Found\n");
    }
  }

  // Non-fixed key detection (not found)
  token = dpi_get_next_token(dpi);
  if (token)
  {
    start = get_current_time();
    etoken = dpi_token_encryption(dpi, token);
    iprint(DPI_DEBUG_MIDDLEBOX, "etoken", (etoken->value), 0, (etoken->len), 16);
    printf("Non-fixed key detection (line-by-line) (not found)\n");
    start = get_current_time();
    for (i=0; i<COUNT; i++)
      tree = dpi_get_current_search_tree(dpi, 0);
    end = get_current_time();
    print_per_interval("Time: tree = dpi_get_current_search_tree(dpi, 0);", start, end);

    start = get_current_time();
    for (i=0; i<COUNT; i++)
      count = 0;
    end = get_current_time();
    print_per_interval("Time: count = 0;", start, end);

    start = get_current_time();
    for (i=0; i<COUNT; i++)
      ret = find_search_tree_token(tree, etoken, &count);
    end = get_current_time();
    print_per_interval("Time: ret = find_search_tree_token(tree, etoken, &count);", start, end);

    start = get_current_time();
    for (i=0; i<COUNT; i++)
      add_search_tree_num_of_fetched(tree);
    end = get_current_time();
    print_per_interval("Time: add_search_tree_num_of_fetched(tree);", start, end);

    printf("ret: %d\n", ret);
    if (ret)
    {
      start = get_current_time();
      for (i=0; i<COUNT; i++)
        table = dpi_get_handle_table(dpi);
      end = get_current_time();
      print_per_interval("Time: table = dpi_get_handle_table(dpi);", start, end);

      start = get_current_time();
      for (i=0; i<COUNT; i++)
        context = dpi_get_security_context(dpi);
      end = get_current_time();
      print_per_interval("Time: context = dpi_get_security_context(dpi);", start, end);

      start = get_current_time();
      for (i=0; i<COUNT; i++)
        salt = get_context_salt(context);
      end = get_current_time();
      print_per_interval("Time: salt = get_context_salt(context);", start, end);

      start = get_current_time();
      for (i=0; i<COUNT; i++)
        rs = get_context_rs_value(context);
      end = get_current_time();
      print_per_interval("Time: rs = get_context_rs_value(context)", start, end);

      start = get_current_time();
      for (i=0; i<COUNT; i++)
        bsize = get_context_block_size(context);
      end = get_current_time();
      print_per_interval("Time: bsize = get_context_block_size(context);", start, end);

      start = get_current_time();
      handle = delete_search_tree_token(tree, etoken);
      end = get_current_time();
      print_per_interval("Time: handle = delete_search_tree_token(tree, etoken);", start, end);

      start = get_current_time();
      for (i=0; i<COUNT; i++)
        entry = find_handle_table_token(table, handle);
      end = get_current_time();
      print_per_interval("Time: table = dpi_get_handle_table(dpi);", start, end);

      // Commented out for the experiment
      /*
      start = get_current_time();
      for (i=0; i<COUNT; i++)
        entry->count++;
      end = get_current_time();
      print_per_interval("Time: entry->count++;", start, end);
      */

      start = get_current_time();
      for (i=0; i<COUNT; i++)
        count = entry->count;
      end = get_current_time();
      print_per_interval("Time: count = entry->count;", start, end);

      start = get_current_time();
      for (i=0; i<COUNT; i++)
        ectx = EVP_CIPHER_CTX_new();
      end = get_current_time();
      print_per_interval("Time: ectx = EVP_CIPHER_CTX_new();", start, end);

      start = get_current_time();
      for (i=0; i<COUNT; i++)
        eevp = get_context_cipher_algorithm(context);
      end = get_current_time();
      print_per_interval("Time: eevp = get_context_cipher_algorithm(context);", start, end);

      start = get_current_time();
      for (i=0; i<COUNT; i++)
        rc = EVP_EncryptInit_ex(ectx, eevp, NULL, handle->value, NULL);
      end = get_current_time();
      print_per_interval("Time: rc = EVP_EncryptInit_ex(ectx, eevp, NULL, handle->value, NULL);", start, end);

      start = get_current_time();
      for (i=0; i<COUNT; i++)
        salt += count;
      end = get_current_time();
      print_per_interval("Time: salt += count;", start, end);

      start = get_current_time();
      for (i=0; i<COUNT; i++)
        VAR_TO_PTR_8BYTES(salt, sbuf);
      end = get_current_time();
      print_per_interval("Time: VAR_TO_PTR_8BYTES(salt, sbuf);", start, end);

      start = get_current_time();
      for (i=0; i<COUNT; i++)
        rc = EVP_EncryptUpdate(ectx, eval, &elen, sbuf, bsize);
      end = get_current_time();
      print_per_interval("Time: rc = EVP_EncryptUpdate(ectx, eval, &elen, sbuf, bsize);", start, end);

      start = get_current_time();
      EVP_CIPHER_CTX_free(ectx);
      end = get_current_time();
      print_per_interval("Time: EVP_CIPHER_CTX_free(ectx);", start, end);

      start = get_current_time();
      for (i=0; i<COUNT; i++)
        uetoken = init_etoken(eval, rs);
      end = get_current_time();
      print_per_interval("Time: uetoken = init_etoken(eval, rs);", start, end);

      start = get_current_time();
      for (i=0; i<COUNT; i++)
        tree = insert_search_tree_token(tree, handle, uetoken);
      end = get_current_time();
      print_per_interval("Time: tree = insert_search_tree_token(tree, handle, uetoken);", start, end);

      imsg(DPI_DEBUG_MIDDLEBOX, "Result: Found");
      printf("Result: Found\n");
    }
    else
    {
      imsg(DPI_DEBUG_MIDDLEBOX, "Result: Not Found");
      printf("Result: Not Found\n");
    }

    /*
    start = get_current_time();
    for (i=0; i<COUNT; i++)
      dpi_token_encryption(dpi, token);
    end = get_current_time();
    val2 = (end - start) / COUNTD;
    printf("Averaged elapsed time (found) (token_encryption): %.2lf ns\n", val2);
    printf("Averaged elapsed time (found) (token_detection): %.2lf ns\n", val1 - val2);
    */
  }

  printf("\n\n\n");
  free_dpi_context(dpi);
  return 0;
}
