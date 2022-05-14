#ifndef __PARAMS_H__
#define __PARAMS_H__

#include <stdint.h>
#include <dpi/dpi_types.h>
#include "conf.h"

struct param_st
{
  uint16_t wlen;
  uint8_t delim;
  uint8_t doff;
  int rs;
  const char *iname;
  const char *rname;
  int clustering_enabled;
  int num_of_clusters;
  int num_of_trees;
  int max_num_of_fetched;
  int prev_num_of_entries;
};

param_t *init_params(conf_t *conf);
void free_params(param_t *param);

void set_param_window_size(param_t *param, uint16_t wlen);
void set_param_delimiter(param_t *param, uint8_t delim);
void set_param_delimiter_offset(param_t *param, uint8_t doff);
void set_param_rs_value(param_t *param, int rs);
void set_param_rule_filename(param_t *param, const char *rname);
void set_param_input_filename(param_t *param, const char *iname);
void set_param_enable_clustering(param_t *param);
void set_param_num_of_clusters(param_t *param, int nc);
void set_param_prev_num_of_entries(param_t *param, int entries);

uint16_t get_param_window_size(param_t *param);
uint8_t get_param_delimiter(param_t *param);
uint8_t get_param_delimiter_offset(param_t *param);
int get_param_rs_value(param_t *param);
const char *get_param_rule_filename(param_t *param);
const char *get_param_input_filename(param_t *param);
int get_param_clustering_enabled(param_t *param);
int get_param_num_of_clusters(param_t *param);
int get_param_num_of_trees(param_t *param);
int get_param_max_num_of_fetched(param_t *param);
int get_param_prev_num_of_entries(param_t *param);

#endif /* __PARAMS_H__ */
