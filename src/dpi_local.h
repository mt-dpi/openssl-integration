#ifndef __DPI_LOCAL_H__
#define __DPI_LOCAL_H__

#include <stdint.h>
#include <pthread.h>
#include <openssl/ssl.h>

#include <dpi/dpi.h>
#include <dpi/dpi_types.h>
#include <dpi/dpi_logger.h>

struct dpi_st 
{
  int role;
  int scheme;
  const char *name;
  int logging_enabled;
  dpi_module_t *module;
  security_context_t *context;
  counter_table_t *table;
  handle_table_t *handles;
  param_t *param;
  msg_t *head;

  // Public parameters for MT-DPI
  uint8_t *rgkey;
  int rgklen;
  uint8_t **certs;
  int nrules;

  // MB's parameter for MT-DPI
  uint8_t *random;
  int rlen;

  // S's parameter for MT-DPI
  uint8_t *skey;
  int sklen;

  int use_tree_updater;
  int running;
  int rule_is_ready;
  pthread_t tu;
  pthread_attr_t attr;

  SSL *ssl;

  logger_t *logger;
};

struct dpi_module_st
{
  rule_preparer_t *rule_preparer;
  tokenizer_t *tokenizer;
  token_encryptor_t *token_encryptor;
  token_detector_t *token_detector;
  tree_updater_t *tree_updater;
};

dpi_module_t *init_dpi_module(conf_t *conf);
void free_dpi_module(dpi_module_t *module);

void *tree_manager_loop(void *data);

#ifdef TEST
void test_function(const char *name);
#endif /* TEST */

#endif /* __DPI_LOCAL_H__ */
