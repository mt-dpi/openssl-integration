#ifndef __DPI_H__
#define __DPI_H__

#define DPI_SCHEME_BLINDBOX       0x1
#define DPI_SCHEME_PRIVDPI        0x2

#define DPI_ROLE_MIDDLEBOX        0x0
#define DPI_ROLE_CLIENT           0x1

#include <stdint.h>
#include <dpi/dpi_types.h>
#include <dpi/dpi_logger.h>
#include <dpi/defines.h>
#include <dpi/params.h>
#include <dpi/conf.h>
#include <openssl/ssl.h>

dpi_t *init_dpi_context(int role, conf_t *conf);
void free_dpi_context(dpi_t *ctx);

const char *dpi_get_name(dpi_t *dpi);

int dpi_rule_preparation(dpi_t *dpi);

// Tokenization-related functions
void dpi_add_message(dpi_t *dpi, uint8_t *msg, int mlen);
token_t *dpi_get_next_token(dpi_t *dpi);
uint8_t *dpi_get_token_value(token_t *token);
int dpi_get_token_length(token_t *token);
int dpi_get_role(dpi_t *dpi);

param_t *dpi_get_params(dpi_t *dpi);
security_context_t *dpi_get_security_context(dpi_t *dpi);
counter_table_t *dpi_get_counter_table(dpi_t *dpi);
void dpi_set_handle_table(dpi_t *dpi, handle_table_t *handles);
handle_table_t *dpi_get_handle_table(dpi_t *dpi);
handle_table_t *dpi_prepare_handle_table(const char *hname);
broker_t *dpi_get_broker(dpi_t *dpi);
int dpi_get_running(dpi_t *dpi);
search_tree_t *dpi_get_search_tree(dpi_t *dpi, int idx);
search_tree_t *dpi_get_current_search_tree(dpi_t *dpi, int cid);
int dpi_get_current_search_tree_idx(dpi_t *dpi, int cid);
void dpi_set_current_search_tree_idx(dpi_t *dpi, int cid, int idx);
int dpi_get_num_of_trees(dpi_t *dpi);
int *dpi_get_search_tree_activeness(dpi_t *dpi);
int *dpi_get_search_tree_cvalues(dpi_t *dpi);
int dpi_update_search_tree(dpi_t *dpi, int idx, int result, int cvalue);
int dpi_update_current_search_tree(dpi_t *dpi, int cid, etoken_t *etoken, int result);
int dpi_get_num_of_clusters(dpi_t *dpi);
int dpi_get_next_cvalue_for_current_search_tree(dpi_t *dpi, int cid);
void dpi_set_search_tree(dpi_t *dpi, int idx, search_tree_t *tree);
int dpi_get_rule_is_ready(dpi_t *dpi);
void dpi_set_rule_is_ready(dpi_t *dpi);
int dpi_get_max_num_of_fetched(dpi_t *dpi);
int dpi_get_is_using_tree_updater(dpi_t *dpi);
void dpi_set_cr_certificates(dpi_t *dpi, uint8_t **certs, int nrules);
void dpi_set_cr_rule_generator_key(dpi_t *dpi, uint8_t *rgkey, int rgklen);
void dpi_set_cr_random_value(dpi_t *dpi, uint8_t *random, int rlen);
void dpi_set_cr_secret_key(dpi_t *dpi, uint8_t *secret, int sklen);
void dpi_set_cr_encryption_key(dpi_t *dpi, uint8_t *secret, int sklen);
void dpi_set_ssl_session(dpi_t *dpi, SSL *ssl);
SSL *dpi_get_ssl_session(dpi_t *dpi);

// Token-encryption-related functions
etoken_t *dpi_token_encryption(dpi_t *dpi, token_t *token);
uint8_t *dpi_get_encrypted_token_value(etoken_t *token);
int dpi_get_encrypted_token_length(etoken_t *token);

int dpi_token_detection(dpi_t *dpi, etoken_t *etoken);

const char *dpi_get_input_filename(dpi_t *dpi);

void dpi_enable_logging(dpi_t *dpi);
void dpi_logger_add(dpi_t *dpi, int name);
void dpi_logger_interval(dpi_t *dpi, int name1, int name2);
void dpi_logger_print(dpi_t *dpi, int name, int flags);
void dpi_logger_print_all(dpi_t *dpi);

#endif /* __DPI_H__ */
