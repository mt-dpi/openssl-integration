#include <dpi/params.h>
#include <dpi/debug.h>
#include <string.h>
#include <stdlib.h>

param_t *init_params(conf_t *conf)
{
  fstart("conf: %p", conf);

  param_t *ret;
  ret = (param_t *)calloc(1, sizeof(param_t));
  ret->wlen = conf->wlen;
  ret->delim = conf->delim;
  ret->doff = conf->doff;
  ret->rs = conf->rs;
  ret->rname = conf->rname;
  ret->iname = conf->iname;
  ret->clustering_enabled = conf->clustering_enabled;
  ret->num_of_clusters = conf->num_of_clusters;
  ret->num_of_trees = conf->num_of_trees;
  ret->max_num_of_fetched = conf->max_num_of_fetched;
  ret->prev_num_of_entries = conf->prev_num_of_entries;

  ffinish("ret: %p", ret);
  return ret;
}

void free_params(param_t *param)
{
  fstart("param: %p", param);

  if (param)
    free(param);

  ffinish();
}

void set_param_window_size(param_t *param, uint16_t wlen)
{
  fstart("param: %p, wlen: %d", param, wlen);
  assert(param != NULL);
  assert(wlen > 0);

  param->wlen = wlen;

  ffinish();
}

void set_param_delimiter(param_t *param, uint8_t delim)
{
  fstart("param: %p, delim: %d", param, delim);
  assert(param != NULL);

  param->delim = delim;

  ffinish();
}

void set_param_delimiter_offset(param_t *param, uint8_t doff)
{
  fstart("param: %p, doff: %d", param, doff);
  assert(param != NULL);
  assert(doff > 0);

  param->doff = doff;

  ffinish();
}

void set_param_rs_value(param_t *param, int rs)
{
  fstart("param: %p, rs: %d", param, rs);
  assert(param != NULL);
  assert(rs > 0);

  param->rs = rs;

  ffinish();
}

void set_param_rule_filename(param_t *param, const char *rname)
{
  fstart("param: %p, rname: %s", param, rname);
  assert(param != NULL);

  param->rname = rname;

  ffinish();
}

void set_param_input_filename(param_t *param, const char *iname)
{
  fstart("param: %p, iname: %s", param, iname);
  assert(param != NULL);

  param->iname = iname;

  ffinish();
}

void set_param_enable_clustering(param_t *param)
{
  fstart("param: %p", param);
  assert(param != NULL);

  param->clustering_enabled = TRUE;

  ffinish();
}

void set_param_num_of_clusters(param_t *param, int nc)
{
  fstart("param: %p, nc: %d", param, nc);
  assert(param != NULL);
  assert(nc > 0);

  param->num_of_clusters = nc;

  ffinish();
}

void set_param_prev_num_of_entries(param_t *param, int entries)
{
  fstart("param: %p, entries: %d", param, entries);
  assert(param != NULL);
  
  param->prev_num_of_entries = entries;

  ffinish();
}

uint16_t get_param_window_size(param_t *param)
{
  fstart("param: %p", param);
  assert(param != NULL);

  uint16_t ret;
  ret = param->wlen;

  ffinish("ret: %u", ret);
  return ret;
}

uint8_t get_param_delimiter(param_t *param)
{
  fstart("param: %p", param);
  assert(param != NULL);

  uint8_t ret;
  ret = param->delim;

  ffinish("ret: %u", ret);
  return ret;
}

uint8_t get_param_delimiter_offset(param_t *param)
{
  fstart("param: %p", param);
  assert(param != NULL);

  uint8_t ret;
  ret = param->doff;

  ffinish("ret: %u", ret);
  return ret;
}

int get_param_rs_value(param_t *param)
{
  fstart("param: %p", param);
  assert(param != NULL);

  int ret;
  ret = param->rs;

  ffinish("ret: %d", ret);
  return ret;
}

const char *get_param_rule_filename(param_t *param)
{
  fstart("param: %p", param);
  assert(param != NULL);

  const char *ret;
  ret = param->rname;

  ffinish("ret: %s", ret);
  return ret;
}

const char *get_param_input_filename(param_t *param)
{
  fstart("param: %p", param);
  assert(param != NULL);

  const char *ret;
  ret = param->iname;

  ffinish("ret: %s", ret);
  return ret;
}

int get_param_clustering_enabled(param_t *param)
{
  fstart("param: %p", param);
  assert(param != NULL);

  int ret;
  ret = param->clustering_enabled;

  ffinish("ret: %d", ret);
  return ret;
}

int get_param_num_of_clusters(param_t *param)
{
  fstart("param: %p", param);
  assert(param != NULL);

  int ret;
  ret = param->num_of_clusters;

  ffinish("ret: %d", ret);
  return ret;
}

int get_param_num_of_trees(param_t *param)
{
  fstart("param: %p", param);
  assert(param != NULL);

  int ret;
  ret = param->num_of_trees;

  ffinish("ret: %d", ret);
  return ret;
}

int get_param_max_num_of_fetched(param_t *param)
{
  fstart("param: %p", param);
  assert(param != NULL);

  int ret;
  ret = param->max_num_of_fetched;

  ffinish("ret: %d", ret);
  return ret;
}

int get_param_prev_num_of_entries(param_t *param)
{
  fstart("param: %p", param);
  assert(param != NULL);

  int ret;
  ret = param->prev_num_of_entries;

  ffinish("ret: %d", ret);
  return ret;
}
