#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <pthread.h>
#include <unistd.h>
#include <time.h>

#include <dpi/dpi.h>
#include <dpi/debug.h>
#include <dpi/parameters.h>
#include <openssl/evp.h>
#include <openssl/rand.h>

#include "etc/security_context.h"
#include "etc/handle_table.h"
#include "etc/counter_table.h"
#include "etc/search_tree.h"
#include "etc/message.h"
#include "etc/pbytes.h"

#include "dpi_local.h"
#include "rule_preparer/rule_preparer.h"
#include "tokenizer/tokenizer.h"
#include "token_encryptor/token_encryptor.h"
#include "token_detector/token_detector.h"
#include "tree_updater/tree_updater.h"

#include "test_values.h"

#ifndef DEBUG_LEVEL
#define DEBUG_LEVEL 2
#endif /* DEBUG_LEVEL */
int dtype = DPI_DEBUG_LIBRARY;

void init_tree_threads(dpi_t *dpi)
{
  fstart("dpi: %p", dpi);

  int rc;

  pthread_attr_init(&(dpi->attr));
  pthread_attr_setdetachstate(&(dpi->attr), PTHREAD_CREATE_JOINABLE);
  dpi->running = TRUE;
  /*
  rc = pthread_create(&(dpi->tm), &(dpi->attr), tree_manager_loop, (void *)dpi);
  if (rc < 0)
  {
    emsg("pthread_create() for the tree manager loop");
    exit(1);
  }
  */

  if (dpi_get_is_using_tree_updater(dpi))
  {
    rc = pthread_create(&(dpi->tu), &(dpi->attr), tree_updater_loop, (void *)dpi);
    if (rc < 0)
    {
      emsg("pthread_create() for the tree updater loop");
      exit(1);
    }
  }

  ffinish();
}

dpi_t *init_dpi_context(int role, conf_t *conf)
{
  fstart("role: %d, conf: %p", role, conf);

  dpi_t *ret;
  int i, sklen, num;
  etoken_t *handle;
  uint64_t salt;
  uint8_t sbuf[8];
  uint8_t buf[5];
  uint8_t secret[16];
  uint8_t *p;
  const char *hname;
  FILE *fp;

  srand(time(NULL));
  ret = (dpi_t *)calloc(1, sizeof(dpi_t));
  ret->role = role;
  ret->param = init_params(conf);
  ret->context = init_security_context();
  ret->use_tree_updater = get_conf_exp_use_tree_updater(conf);
  ret->logger = NULL;
  ret->name = get_conf_module_dpi_name(conf);
  ret->module = init_dpi_module(conf);
  hname = NULL;
  fp = NULL;

  if (get_conf_exp_local_test(conf))
  {
    ret->table = init_counter_table(ret->param);
    ret->handles = init_handle_table();
  }
  else
  {
    if (role == DPI_ROLE_CLIENT)
    {
      ret->table = init_counter_table(ret->param);
    }
    else if (role == DPI_ROLE_MIDDLEBOX)
    {
      ret->handles = init_handle_table();
      /*
      hname = get_conf_param_handle_filename(conf);
      if (hname)
      {
        fp = fopen(hname, "rb");
        fread(buf, 4, 1, fp);
        p = buf;
        PTR_TO_VAR_4BYTES(p, num);
        imsg(DPI_DEBUG_LIBRARY, "# of handles: %d", num);
        
        for (i=0; i<num; i++)
        {
          fread(buf, 5, 1, fp);
          handle = init_etoken(buf, 5);
          add_handle_table_token(ret->handles, handle);
        }
        fclose(fp);
        fp = NULL;
      }
      */
    }
  }

  if (role == DPI_ROLE_MIDDLEBOX)
    set_context_rgrand(ret->context, rgrand, sizeof(rgrand));

  set_context_cipher_algorithm(ret->context, EVP_aes_128_ecb());
  set_context_rs_value(ret->context, ret->param->rs);
  if (get_conf_exp_use_hardcoded_keys(conf))
  {
    imsg(DPI_DEBUG_LIBRARY, "Hardcode keys are used");
    imsg(DPI_DEBUG_LIBRARY, "Salt: %d", test_salt);
    iprint(DPI_DEBUG_LIBRARY, "Encryption Key", test_key, 0, sizeof(test_key), 16);
    iprint(DPI_DEBUG_LIBRARY, "Secret", test_skey, 0, sizeof(test_skey), 16);
    set_context_salt(ret->context, test_salt);
    set_context_encryption_key(ret->context, test_key, 16);
    set_context_encryption_context(ret->context);
    set_context_secret(ret->context, test_skey, 16);
    set_context_secret_context(ret->context);
  }
  else
  {
    imsg(DPI_DEBUG_LIBRARY, "Hardcode keys are not used");
    RAND_bytes(sbuf, 8);
    PTR_TO_VAR_8BYTES(sbuf, salt);
    sklen = 16;
    RAND_bytes(secret, sklen);

    set_context_salt(ret->context, salt);
    set_context_encryption_key(ret->context, rgkey, sizeof(rgkey));
    set_context_encryption_context(ret->context);
    // Added for the token computation experiment
    iprint(DPI_DEBUG_LIBRARY, "Secret", secret, 0, sizeof(secret), 16);
    set_context_secret(ret->context, secret, sizeof(secret));
    set_context_secret_context(ret->context);
  }

  if (role != DPI_ROLE_CLIENT)
  {
    if (ret->use_tree_updater)
      init_tree_threads(ret);
  }

  dmsg(DPI_DEBUG_MIDDLEBOX, "DPI %s is initialized", ret->name);
  ffinish("ret: %p", ret);
  return ret;
}

void stop_tree_threads(dpi_t *dpi)
{
  fstart("dpi: %p", dpi);
  assert(dpi != NULL);

  int rc; 
  void *status;

  dpi->running = FALSE;
  if (dpi->use_tree_updater)
  {
    rc = pthread_join(dpi->tu, &status);

    if (rc)
      emsg("return code from pthread_join: %d", rc);
  }

  ffinish();
}

void free_dpi_context(dpi_t *ctx)
{
  fstart("ctx: %p", ctx);
  assert(ctx != NULL);

  if (ctx)
  {
    if (ctx->context)
      free_security_context(ctx->context);

    if (ctx->table)
      free_counter_table(ctx->table);

    if (ctx->handles)
      free_handle_table(ctx->handles);

    if (ctx->param)
      free_params(ctx->param);

    if (ctx->head)
      free_messages(ctx->head);

    if (ctx->logger)
      fin_logger(ctx->logger);

    if (ctx->running)
      stop_tree_threads(ctx);

    if (ctx->module)
      free_dpi_module(ctx->module);

    free(ctx);
  }

  ffinish();
}

dpi_module_t *init_dpi_module(conf_t *conf)
{
  fstart("conf: %p", conf);
  dpi_module_t *ret;

  ret = (dpi_module_t *)calloc(1, sizeof(dpi_module_t));
  ret->rule_preparer = init_rule_preparer(conf);
  ret->tokenizer = init_tokenizer(conf);
  ret->token_encryptor = init_token_encryptor(conf);
  ret->token_detector = init_token_detector(conf);
  ret->tree_updater = init_tree_updater(conf);

  ffinish("ret: %p", ret);
  return ret;
}

void free_dpi_module(dpi_module_t *module)
{
  fstart("module: %p", module);

  if (module)
  {
    if (module->rule_preparer)
      free_rule_preparer(module->rule_preparer);
    if (module->tokenizer)
      free_tokenizer(module->tokenizer);
    if (module->token_encryptor)
      free_token_encryptor(module->token_encryptor);
    if (module->token_detector)
      free_token_detector(module->token_detector);
    if (module->tree_updater)
      free_tree_updater(module->tree_updater);
  }

  ffinish();
}

const char *dpi_get_name(dpi_t *dpi)
{
  fstart("dpi: %p", dpi);
  const char *ret;
  ret = dpi->name;
  ffinish("ret: %p", ret);
  return ret;
}

param_t *dpi_get_params(dpi_t *dpi)
{
  fstart("dpi: %p", dpi);
  assert(dpi != NULL);

  param_t *ret;
  ret = dpi->param;

  ffinish("ret: %p", ret);
  return ret;
}

security_context_t *dpi_get_security_context(dpi_t *dpi)
{
  fstart("dpi: %p", dpi);

  security_context_t *ret;
  ret = dpi->context;

  ffinish("ret: %p", ret);
  return ret;
}

counter_table_t *dpi_get_counter_table(dpi_t *dpi)
{
  fstart("dpi: %p", dpi);

  counter_table_t *ret;
  ret = dpi->table;

  ffinish("ret: %p", ret);
  return ret;
}

handle_table_t *dpi_get_handle_table(dpi_t *dpi)
{
  fstart("dpi: %p", dpi);

  handle_table_t *ret;
  ret = dpi->handles;

  ffinish("ret: %p", ret);
  return ret;
}

int dpi_get_running(dpi_t *dpi)
{
  fstart("dpi: %p", dpi);
  assert(dpi != NULL);

  int ret;
  ret = dpi->running;

  ffinish("ret: %d", ret);
  return ret;
}

int dpi_get_num_of_trees(dpi_t *dpi)
{
  fstart("dpi: %p", dpi);
  assert(dpi != NULL);
    
  int ret;
  ret = dpi->module->tree_updater->num_of_trees;

  ffinish("ret: %d", ret);
  return ret;
}

int dpi_get_num_of_clusters(dpi_t *dpi)
{
  fstart("dpi: %p", dpi);
  assert(dpi != NULL);
    
  int ret;
  ret = dpi->module->tree_updater->num_of_clusters;

  ffinish("ret: %d", ret);
  return ret;
}

search_tree_t *dpi_get_search_tree(dpi_t *dpi, int idx)
{
  fstart("dpi: %p", dpi);
  assert(dpi != NULL);

  search_tree_t *ret;
  ret = dpi->module->tree_updater->trees[idx];

  ffinish("ret: %p", ret);
  return ret;
}

int dpi_get_current_search_tree_idx(dpi_t *dpi, int cid)
{
  fstart("dpi: %p, cid: %d", dpi, cid);
  assert(dpi != NULL);

  int ret;
  ret = dpi->module->tree_updater->idx[cid];

  ffinish("ret: %d", ret);
  return ret;
}

void dpi_set_current_search_tree_idx(dpi_t *dpi, int cid, int idx)
{
  fstart("dpi: %p, idx: %d", dpi, idx);
  assert(dpi != NULL);
  
  dpi->module->tree_updater->idx[cid] = idx;

  ffinish();
}

search_tree_t *dpi_get_current_search_tree(dpi_t *dpi, int cid)
{
  fstart("dpi: %p, cid: %d", dpi, cid);
  assert(dpi != NULL);

  search_tree_t *ret;
  int idx;
  int *active;
  int num_of_clusters;
  idx = dpi->module->tree_updater->idx[cid];
  active = dpi->module->tree_updater->active;
  num_of_clusters = dpi_get_num_of_clusters(dpi);

  if (dpi_get_is_using_tree_updater(dpi) && num_of_clusters > 1)
    while (active[idx] == 0) {}

  ret = dpi->module->tree_updater->trees[idx];

  ffinish("ret: %p", ret);
  return ret;
}

int dpi_get_next_cvalue_for_current_search_tree(dpi_t *dpi, int cid)
{
  fstart("dpi: %p", dpi);
  assert(dpi != NULL);

  int ret;
  dpi->module->tree_updater->cvalue[cid] += 1;
  ret = dpi->module->tree_updater->cvalue[cid];

  ffinish("ret: %d", ret);
  return ret;
}

int dpi_get_max_num_of_fetched(dpi_t *dpi)
{
  fstart("dpi: %p", dpi);
  assert(dpi != NULL);

  int ret;
  ret = dpi->param->max_num_of_fetched;

  ffinish("ret: %d", ret);
  return ret;
}

int dpi_get_is_using_tree_updater(dpi_t *dpi)
{
  fstart("dpi: %p", dpi);
  assert(dpi != NULL);

  int ret;
  ret = dpi->use_tree_updater;

  ffinish("ret: %d", ret);
  return ret;
}

void dpi_set_cr_certificates(dpi_t *dpi, uint8_t **certs, int nrules)
{
  dpi->certs = certs;
  dpi->nrules = nrules;
}

void dpi_set_cr_rule_generator_key(dpi_t *dpi, uint8_t *rgkey, int rgklen)
{
  dpi->rgkey = rgkey;
  dpi->rgklen = rgklen;
}

void dpi_set_cr_random_value(dpi_t *dpi, uint8_t *random, int rlen)
{
  dpi->random = random;
  dpi->rlen = rlen;
}

void dpi_set_cr_encryption_key(dpi_t *dpi, uint8_t *ekey, int eklen)
{
  set_context_encryption_key(dpi->context, ekey, eklen);
  set_context_encryption_context(dpi->context);
}

void dpi_set_cr_secret_key(dpi_t *dpi, uint8_t *secret, int sklen)
{
  set_context_secret(dpi->context, secret, sklen);
  set_context_secret_context(dpi->context);
}

void dpi_set_ssl_session(dpi_t *dpi, SSL *ssl)
{
  dpi->ssl = ssl;
}

void dpi_set_handle_table(dpi_t *dpi, handle_table_t *handles)
{
  fstart("dpi: %p, handles: %p", dpi, handles);

  dpi->handles = handles;

  ffinish();
}

handle_table_t *dpi_prepare_handle_table(const char *hname)
{
  fstart("hname: %s", hname);
  int i, num;
  handle_table_t *ret;
  FILE *fp;
  uint8_t buf[16];
  uint8_t *p;
  etoken_t *handle;

  ret = init_handle_table();
  assert(ret != NULL);
  fp = fopen(hname, "rb");
  fread(buf, 4, 1, fp);
  p = buf;
  PTR_TO_VAR_4BYTES(p, num);
  imsg(DPI_DEBUG_LIBRARY, "# of handles: %d", num);

  for (i=0; i<num; i++)
  {
    fread(buf, 16, 1, fp);
    handle = init_etoken(buf, 16);
    add_handle_table_token(ret, handle);
  }
  fclose(fp);
  fp = NULL;

  ffinish("ret: %p", ret);
  return ret;
}

SSL *dpi_get_ssl_session(dpi_t *dpi)
{
  return dpi->ssl;
}

void dpi_set_search_tree(dpi_t *dpi, int idx, search_tree_t *tree)
{
  fstart("dpi: %p, idx: %d, tree: %p", dpi, idx, tree);

  dpi->module->tree_updater->trees[idx] = tree;

  ffinish();
}

broker_t *dpi_get_broker(dpi_t *dpi)
{
  fstart("dpi: %p", dpi);

  broker_t *ret;
  ret = dpi->module->tree_updater->broker;

  ffinish("ret: %p", ret);
  return ret;
}

// Message-related functions
void dpi_add_message(dpi_t *dpi, uint8_t *msg, int mlen)
{
  fstart("dpi: %p, msg: %p, mlen: %d", dpi, msg, mlen);
  assert(dpi != NULL);
  assert(msg != NULL);
  assert(mlen > 0);

  msg_t *p, *new;
  security_context_t *context;
  int bsize;
  
  context = dpi_get_security_context(dpi);
  bsize = get_context_block_size(context);
  new = init_message(msg, mlen, bsize, dpi->param);
  printf("new: %p, new->mlen: %d, new->bsize: %d, dpi->head: %p\n", new, new->mlen, new->bsize, dpi->head);

  p = dpi->head;

  if (!p)
  {
    dpi->head = new;
  }
  else
  {
    while (p)
    {
      if (!(p->next))
      {
        p->next = new;
        break;
      }
      p = p->next;
    }
  }

  ffinish();
}

msg_t *dpi_get_current_message(dpi_t *dpi)
{
  fstart("dpi: %p", dpi);

  msg_t *ret, *p, *q;
  p = dpi->head;

  if (p && p->processed && (p->offset >= p->mlen))
  {
    q = p;
    if (p->next)
      p = p->next;
    else
      p = NULL;
    free_message(q);
  }

  ret = p;
  if (p)
    p->processed = TRUE;

  ffinish("ret: %p", ret);
  return ret;
}

int dpi_rule_preparation(dpi_t *dpi)
{
  fstart("dpi: %p", dpi);
  assert(dpi != NULL);

  int ret;
  ret = dpi->module->rule_preparer->rule_preparation(dpi);

  ffinish("ret: %d", ret);
  return ret;
}

// Tokenization-related functions
token_t *dpi_get_next_token(dpi_t *dpi)
{
  fstart("dpi: %p", dpi);

  token_t *ret;
  msg_t *msg;

  msg = dpi_get_current_message(dpi);
  if (msg)
    ret = dpi->module->tokenizer->get_next_token(msg);
  else
    ret = NULL;

  ffinish("ret: %p", ret);
  return ret;
}

uint8_t *dpi_get_token_value(token_t *token)
{
  fstart("token: %p", token);
  assert(token != NULL);

  uint8_t *ret;
  ret = token->value;

  ffinish("ret: %p", ret);
  return ret;
}

int dpi_get_token_length(token_t *token)
{
  fstart("token: %p", token);
  assert(token != NULL);

  int ret;
  ret = token->len;

  ffinish("ret: %d", ret);
  return ret;
}

int dpi_get_role(dpi_t *dpi)
{
  fstart("dpi: %p", dpi);
  assert(dpi != NULL);

  int ret;
  ret = dpi->role;

  ffinish("ret: %d", ret);
  return ret;
}

// Token encryption-related functions
uint8_t *dpi_get_encrypted_token_value(etoken_t *token)
{
  fstart("token: %p", token);
  assert(token != NULL);

  uint8_t *ret;
  ret = token->value;

  ffinish("ret: %p", ret);
  return ret;
}

int dpi_get_encrypted_token_length(etoken_t *token)
{
  fstart("token: %p", token);
  assert(token != NULL);

  int ret;
  ret = token->len;

  ffinish("ret: %d", ret);
  return ret;
}

etoken_t *dpi_token_encryption(dpi_t *dpi, token_t *token)
{
  fstart("dpi: %p, token: %p", dpi, token);
  assert(dpi != NULL);
  assert(token != NULL);
  
  etoken_t *ret;
  ret = dpi->module->token_encryptor->token_encryption(dpi, token);

  ffinish("ret: %p", ret);
  return ret;
}

int dpi_token_detection(dpi_t *dpi, etoken_t *etoken)
{
  fstart("dpi: %p, etoken: %p", dpi, etoken);
  assert(dpi != NULL);
  assert(etoken != NULL);

  int ret;
  ret = FALSE;
  ret = dpi->module->token_detector->token_detection(dpi, etoken);

  ffinish("ret: %d", ret);
  return ret;
}

int dpi_update_search_tree(dpi_t *dpi, int idx, int result, int cvalue)
{
  fstart("dpi: %p, idx: %d, result: %d, cvalue: %d", dpi, idx, result, cvalue);
  assert(dpi != NULL);
  assert(idx >= 0);

  int ret;
  ret = dpi->module->tree_updater->tree_update(dpi, NULL, idx, result, cvalue);

  ffinish("ret: %d", ret);
  return ret;
}

int dpi_update_current_search_tree(dpi_t *dpi, int cid, etoken_t *etoken, int result)
{
  fstart("dpi: %p, etoken: %p, result: %d", dpi, etoken, result);
  assert(dpi != NULL);

  int ret, idx, cvalue;
  idx = dpi->module->tree_updater->idx[cid];
  cvalue = dpi_get_next_cvalue_for_current_search_tree(dpi, cid);
  ret = dpi->module->tree_updater->tree_update(dpi, etoken, idx, result, cvalue);

  ffinish("ret: %d", ret);
  return ret;
}

int *dpi_get_search_tree_activeness(dpi_t *dpi)
{
  fstart("dpi: %p", dpi);
  assert(dpi != NULL);
  
  int *ret;
  ret = dpi->module->tree_updater->active;

  ffinish("ret: %p", ret);
  return ret;
}

int *dpi_get_search_tree_cvalues(dpi_t *dpi)
{
  fstart("dpi: %p", dpi);
  assert(dpi != NULL);

  int *ret;
  ret = dpi->module->tree_updater->cvalue;

  ffinish("ret: %p", ret);
  return ret;
}

void dpi_enable_logging(dpi_t *dpi)
{
  fstart("dpi: %p", dpi);

  dpi->logging_enabled = TRUE;

  ffinish();
}

void dpi_logger_add(dpi_t *dpi, int name)
{
  fstart("dpi: %p, name: %d", dpi, name);
  assert(dpi != NULL);

  dpi->logger->ops->add(dpi->logger, name);

  ffinish();
}

void dpi_logger_interval(dpi_t *dpi, int name1, int name2)
{
  fstart("dpi: %p, name1: %d, name2: %d", dpi, name1, name2);
  assert(dpi != NULL);
  
  dpi->logger->ops->interval(dpi->logger, name1, name2);

  ffinish();
}

void dpi_logger_print(dpi_t *dpi, int name, int flags)
{
  fstart("dpi: %p", dpi);
  assert(dpi != NULL);
  assert(flags >= 0);

  dpi->logger->ops->print(dpi->logger, name, flags);

  ffinish();
}

void dpi_logger_print_all(dpi_t *dpi)
{
  fstart("dpi: %p", dpi);
  assert(dpi != NULL);

  dpi->logger->ops->print_all(dpi->logger);

  ffinish();
}

const char *dpi_get_input_filename(dpi_t *dpi)
{
  fstart("dpi: %p", dpi);
  assert(dpi != NULL);

  const char *ret;
  ret = get_param_input_filename(dpi->param);

  ffinish("ret: %s", ret);
  return ret;
}

int dpi_get_rule_is_ready(dpi_t *dpi)
{
  fstart("dpi: %p", dpi);
  assert(dpi != NULL);
  
  int ret;
  ret = dpi->rule_is_ready;

  ffinish("ret: %d", ret);
  return ret;
}

void dpi_set_rule_is_ready(dpi_t *dpi)
{
  fstart("dpi: %p", dpi);
  assert(dpi != NULL);

  dpi->rule_is_ready = TRUE;

  ffinish();
}
