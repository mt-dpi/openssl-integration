#ifndef __CONF_H__
#define __CONF_H__

#include <dpi/dpi_types.h>
#include <dpi/dpi.h>

struct dpi_conf_st
{
  const char *name;
  int rule_preparation_idx;
  int get_next_token_idx;
  int token_encryption_idx;
  int token_detection_idx;
  int tree_update_idx;

  uint16_t wlen;
  uint16_t tlen;
  uint8_t delim;
  uint8_t doff;
  int rs;

  const char *rname;
  const char *iname;
  const char *hname;

  const char *log_directory;
  const char *log_prefix;
  const char *mname;
  int flags;

  int num_of_trees;
  int clustering_enabled;
  int num_of_clusters;
  int max_num_of_fetched;
  int prev_num_of_entries;

  int logging_enabled;
  int local_test;
  int use_hardcoded_keys;
  int use_tree_updater;
};

conf_t *init_conf_module(void);
void set_conf_module(conf_t *conf, int argc, char *argv[]);
void free_conf_module(conf_t *conf);

void set_conf_module_dpi_name(conf_t *conf, const char *name);
void set_conf_module_rule_preparation_idx(conf_t *conf, int idx);
void set_conf_module_get_next_token_idx(conf_t *conf, int idx);
void set_conf_module_token_encryption_idx(conf_t *conf, int idx);
void set_conf_module_token_detection_idx(conf_t *conf, int idx);
void set_conf_module_tree_update_idx(conf_t *conf, int idx);
void set_conf_log_directory(conf_t *conf, const char *ldir);
void set_conf_log_prefix(conf_t *conf, const char *lprefix);
void set_conf_log_messages(conf_t *conf, const char *msgs);
void set_conf_log_flags(conf_t *conf, int flags);
void set_conf_log_enable_logging(conf_t *conf);
void set_conf_param_rule_filename(conf_t *conf, const char *rname);
void set_conf_param_input_filename(conf_t *conf, const char *iname);
void set_conf_param_handle_filename(conf_t *conf, const char *hname);
void set_conf_param_window_size(conf_t *conf, int wsize);
void set_conf_param_token_size(conf_t *conf, int tsize);
void set_conf_param_enable_clustering(conf_t *conf);
void set_conf_param_num_of_clusters(conf_t *conf, int nc);
void set_conf_param_num_of_trees(conf_t *conf, int nt);
void set_conf_param_max_num_of_fetched(conf_t *conf, int nf);
void set_conf_exp_local_test(conf_t *conf);
void set_conf_exp_use_hardcoded_keys(conf_t *conf);
void set_conf_exp_use_tree_updater(conf_t *conf);
void set_conf_exp_prev_num_of_entries(conf_t *conf, int entries);

const char *get_conf_module_dpi_name(conf_t *conf);
int get_conf_module_rule_preparation_idx(conf_t *conf);
int get_conf_module_get_next_token_idx(conf_t *conf);
int get_conf_module_token_encryption_idx(conf_t *conf);
int get_conf_module_token_detection_idx(conf_t *conf);
int get_conf_module_tree_update_idx(conf_t *conf);
const char *get_conf_log_directory(conf_t *conf);
const char *get_conf_log_prefix(conf_t *conf);
const char *get_conf_log_messages(conf_t *conf);
int get_conf_log_flags(conf_t *conf);
int get_conf_log_logging_enabled(conf_t *conf);
const char *get_conf_param_rule_filename(conf_t *conf);
const char *get_conf_param_input_filename(conf_t *conf);
const char *get_conf_param_handle_filename(conf_t *conf);
int get_conf_param_window_size(conf_t *conf);
int get_conf_param_token_size(conf_t *conf);
int get_conf_param_clustering_enabled(conf_t *conf);
int get_conf_param_num_of_clusters(conf_t *conf);
int get_conf_param_num_of_trees(conf_t *conf);
int get_conf_param_max_num_of_fetched(conf_t *conf);
int get_conf_exp_local_test(conf_t *conf);
int get_conf_exp_use_hardcoded_keys(conf_t *conf);
int get_conf_exp_use_tree_updater(conf_t *conf);
int get_conf_exp_prev_num_of_entries(conf_t *conf);

#endif /* __CONF_H__ */
