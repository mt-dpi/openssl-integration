#include "conf.h"
#include <stdlib.h>
#include <string.h>
#include <getopt.h>
#include <dpi/debug.h>

int dpi_conf_usage(const char *pname)
{
  emsg(">> Usage: %s [options]", pname);
  emsg("Options");
  emsg("  -a, --rule-preparation    Rule Preparation");
  emsg("  -b, --get-next-token      Get Next Token");
  emsg("  -c, --token-encryption    Token Encryption");
  emsg("  -d, --token-detection     Token Detection");
  emsg("  -e, --tree-update         Tree Update");
  emsg("  -n, --name                DPI Name");
  emsg("  -r, --rule                Rule Filename");
  emsg("  -i, --input-filename      Input Filename");
  emsg("  -h, --handle-filename     Handle Filename");
  emsg("  -l, --logging             Enable Logging");
  emsg("  -t, --local-test          Local Test");
  emsg("  -k, --use-hardcoded-keys  Use Hardcoded Keys");
  emsg("  -u, --num-of-trees        Number of Trees");
  emsg("  -w, --window-size         Window Size");
  emsg("  -s, --token-size          Token Size");
  emsg("  -y, --clustering          Enable Clustering Rules");
  emsg("  -z, --num-of-clusters     Number of Clusters");
  emsg("  -f, --max-num-of-fetched  Maximum Number of Fetched");
  emsg("  -j, --use-tree-updater    Use tree updater");
  emsg("  -q, --prev-num-of-entries Num of Entries Inserted in a Counter Table");
  exit(1);
}

conf_t *init_conf_module(void)
{
  fstart();
  
  conf_t *ret;
  ret = (conf_t *)calloc(1, sizeof(conf_t));

  ffinish("ret: %p", ret);
  return ret;
}

void set_conf_module(conf_t *conf, int argc, char *argv[])
{
  fstart("conf: %p, argc: %d, argv: %p", conf, argc, argv);
  assert(conf != NULL);
  assert(argv != NULL);

  const char *pname;
  char *name, *iname, *rname, *hname, *lname, *mname, *lprefix;
  int c, rpidx, tnidx, teidx, tdidx, tuidx, wlen, tlen, flags, clustering, nc, nt, mf, ne;

  pname = argv[0];

  name = NULL;
  iname = NULL;
  rname = NULL;
  hname = NULL;

  lname = NULL;
  mname = NULL;
  lprefix = NULL;

  clustering = FALSE;

  rpidx = -1;
  tnidx = -1;
  teidx = -1;
  tdidx = -1;
  tuidx = -1;
  wlen = -1;
  tlen = -1;
  flags = -1;
  nc = -1;
  nt = -1;
  mf = -1;

  while (1)
  {
    int option_index = 0;
    static struct option long_options[] = {
      {"rule-preparation", required_argument, 0, 'a'},
      {"get-next-token", required_argument, 0, 'b'},
      {"token-encryption", required_argument, 0, 'c'},
      {"token-detection", required_argument, 0, 'd'},
      {"tree-update", required_argument, 0, 'e'},
      {"name", required_argument, 0, 'n'},
      {"rule-filename", required_argument, 0, 'r'},
      {"input-filename", required_argument, 0, 'i'},
      {"logging", no_argument, 0, 'l'},
      {"log-directory", required_argument, 0, 'o'},
      {"log-prefix", required_argument, 0, 'p'},
      {"log-messages", required_argument, 0, 'm'},
      {"log-flags", required_argument, 0, 'f'},
      {"local-test", no_argument, 0, 't'},
      {"use-hardcoded-keys", no_argument, 0, 'k'},
      {"window-size", required_argument, 0, 'w'},
      {"token-size", required_argument, 0, 's'},
      {"clustering", no_argument, 0, 'y'},
      {"num-of-clusters", required_argument, 0, 'z'},
      {"num-of-trees", required_argument, 0, 'u'},
      {"max-num-of-fetched", required_argument, 0, 'g'},
      {"use-tree-updater", no_argument, 0, 'j'},
      {"prev-num-of-entries", required_argument, 0, 'q'},
      {0, 0, 0, 0}
    };

    const char *opt = "a:b:c:d:e:n:r:i:lo:p:m:f:tkw:s:yz:u:g:jq:h:0";

    c = getopt_long(argc, argv, opt, long_options, &option_index);

    if (c == -1)
      break;
    
    switch (c)
    {
      case 'a':
        rpidx = atoi(optarg);
        set_conf_module_rule_preparation_idx(conf, rpidx);
        break;

      case 'b':
        tnidx = atoi(optarg);
        set_conf_module_get_next_token_idx(conf, tnidx);
        break;

      case 'c':
        teidx = atoi(optarg);
        set_conf_module_token_encryption_idx(conf, teidx);
        break;

      case 'd':
        tdidx = atoi(optarg);
        set_conf_module_token_detection_idx(conf, tdidx);
        break;

      case 'e':
        tuidx = atoi(optarg);
        set_conf_module_tree_update_idx(conf, tuidx);
        break;

      case 'n':
        name = optarg;
        set_conf_module_dpi_name(conf, name);
        break;

      case 'r':
        rname = optarg;
        set_conf_param_rule_filename(conf, rname);
        break;

      case 'i':
        iname = optarg;
        set_conf_param_input_filename(conf, iname);
        break;

      case 'h':
        hname = optarg;
        set_conf_param_handle_filename(conf, hname);
        break;

      case 'l':
        set_conf_log_enable_logging(conf);
        break;

      case 'o':
        lname = optarg;
        set_conf_log_directory(conf, lname);
        break;

      case 'p':
        lprefix = optarg;
        set_conf_log_prefix(conf, lprefix);
        break;

      case 'm':
        mname = optarg;
        set_conf_log_messages(conf, mname);
        break;

      case 'f':
        flags = atoi(optarg);
        set_conf_log_flags(conf, flags);
        break;

      case 't':
        set_conf_exp_local_test(conf);
        break;

      case 'k':
        set_conf_exp_use_hardcoded_keys(conf);
        break;

      case 'w':
        wlen = atoi(optarg);
        set_conf_param_window_size(conf, wlen);
        break;

      case 's':
        tlen = atoi(optarg);
        set_conf_param_token_size(conf, tlen);
        break;

      case 'u':
        nt = atoi(optarg);
        set_conf_param_num_of_trees(conf, nt);
        break;

      case 'y':
        set_conf_param_enable_clustering(conf);
        clustering = TRUE;
        break;

      case 'z':
        nc = atoi(optarg);
        set_conf_param_num_of_clusters(conf, nc);
        break;

      case 'g':
        mf = atoi(optarg);
        set_conf_param_max_num_of_fetched(conf, mf);
        break;

      case 'j':
        set_conf_exp_use_tree_updater(conf);
        break;

      case 'q':
        ne = atoi(optarg);
        set_conf_exp_prev_num_of_entries(conf, ne);
        break;

      default:
        dpi_conf_usage(pname);
    }
  }

  if (!name)
  {
    emsg("DPI name is not set");
    dpi_conf_usage(pname);
  }

  if (!rname)
  {
    emsg("The rule filename is not set");
    dpi_conf_usage(pname);
  }

  if (!iname)
  {
    emsg("The input filename is not set");
    dpi_conf_usage(pname);
  }

  if (rpidx < 0)
  {
    emsg("The rule preparation function is not set");
    dpi_conf_usage(pname);
  }

  if (tnidx < 0)
  {
    emsg("The tokenization function is not set");
    dpi_conf_usage(pname);
  }

  if (teidx < 0)
  {
    emsg("The token encryption function is not set");
    dpi_conf_usage(pname);
  }

  if (tdidx < 0)
  {
    emsg("The token detection function is not set");
    dpi_conf_usage(pname);
  }

  if (tuidx < 0)
  {
    emsg("The tree update function is not set");
    dpi_conf_usage(pname);
  }

  if (wlen < 0)
  {
    emsg("The window length is not set");
    dpi_conf_usage(pname);
  }

  if (tlen < 0)
  {
    emsg("The encrypted token length is not set");
    dpi_conf_usage(pname);
  }

  if (flags < 0)
  {
    emsg("The log flag is not set");
    dpi_conf_usage(pname);
  }

  if (clustering && nc < 0)
  {
    emsg("The number of clusters should be set if clustering is enabled");
    dpi_conf_usage(pname);
  }

  if (clustering && mf < 0)
  {
    emsg("The maximum number of fetched should be set if clustering is enabled");
    dpi_conf_usage(pname);
  }

  if (clustering && (!(nt >= nc && nt % nc == 0)))
  {
    emsg("The number of trees should be multiple of the number of clusters if clustering is enabled");
    dpi_conf_usage(pname);
  }
}

void free_conf_module(conf_t *conf)
{
  fstart("conf: %p", conf);

  if (conf)
  {
    free(conf);
  }

  ffinish();
}

void set_conf_module_dpi_name(conf_t *conf, const char *name)
{
  fstart("conf: %p, name: %s", conf, name);
  assert(conf != NULL);

  conf->name = name;

  ffinish();
}

void set_conf_module_rule_preparation_idx(conf_t *conf, int idx)
{
  fstart("conf: %p, idx: %d", conf, idx);
  assert(conf != NULL);

  conf->rule_preparation_idx = idx;

  ffinish();
}

void set_conf_module_get_next_token_idx(conf_t *conf, int idx)
{
  fstart("conf: %p, idx: %d", conf, idx);
  assert(conf != NULL);

  conf->get_next_token_idx = idx;

  ffinish();
}

void set_conf_module_token_encryption_idx(conf_t *conf, int idx)
{
  fstart("conf: %p, idx: %d", conf, idx);
  assert(conf != NULL);

  conf->token_encryption_idx = idx;

  ffinish();
}

void set_conf_module_token_detection_idx(conf_t *conf, int idx)
{
  fstart("conf: %p, idx: %d", conf, idx);
  assert(conf != NULL);

  conf->token_detection_idx = idx;

  ffinish();
}

void set_conf_module_tree_update_idx(conf_t *conf, int idx)
{
  fstart("conf: %p, idx: %d", conf, idx);
  assert(conf != NULL);

  conf->tree_update_idx = idx;

  ffinish();
}

const char *get_conf_module_dpi_name(conf_t *conf)
{
  fstart("conf: %p", conf);
  assert(conf != NULL);

  const char *ret;
  ret = conf->name;

  ffinish("ret: %s", ret);
  return ret;
}

int get_conf_module_rule_preparation_idx(conf_t *conf)
{
  fstart("conf: %p", conf);
  assert(conf != NULL);

  int ret;
  ret = conf->rule_preparation_idx;

  ffinish("ret: %d", ret);
  return ret;
}

int get_conf_module_get_next_token_idx(conf_t *conf)
{
  fstart("conf: %p", conf);
  assert(conf != NULL);

  int ret;
  ret = conf->get_next_token_idx;

  ffinish("ret: %d", ret);
  return ret;
}

int get_conf_module_token_encryption_idx(conf_t *conf)
{
  fstart("conf: %p", conf);
  assert(conf != NULL);

  int ret;
  ret = conf->token_encryption_idx;

  ffinish("ret: %d", ret);
  return ret;
}

int get_conf_module_token_detection_idx(conf_t *conf)
{
  fstart("conf: %p", conf);
  assert(conf != NULL);

  int ret;
  ret = conf->token_detection_idx;

  ffinish("ret: %d", ret);
  return ret;
}

int get_conf_module_tree_update_idx(conf_t *conf)
{
  fstart("conf: %p", conf);
  assert(conf != NULL);

  int ret;
  ret = conf->tree_update_idx;

  ffinish("ret: %d", ret);
  return ret;
}

void set_conf_log_directory(conf_t *conf, const char *ldir)
{
  fstart("conf: %p, ldir: %s", conf, ldir);
  assert(conf != NULL);

  conf->log_directory = ldir;

  ffinish();
}

void set_conf_log_prefix(conf_t *conf, const char *lprefix)
{
  fstart("conf: %p, lprefix: %s", conf, lprefix);
  assert(conf != NULL);

  conf->log_prefix = lprefix;

  ffinish();
}

void set_conf_log_messages(conf_t *conf, const char *msgs)
{
  fstart("conf: %p, msgs: %s", conf, msgs);
  assert(conf != NULL);

  conf->mname = msgs;

  ffinish();
}

void set_conf_log_flags(conf_t *conf, int flags)
{
  fstart("conf: %p, flags: %d", conf, flags);
  assert(conf != NULL);

  conf->flags = flags;

  ffinish();
}

void set_conf_log_enable_logging(conf_t *conf)
{
  fstart("conf: %p", conf);
  assert(conf != NULL);

  conf->logging_enabled = TRUE;

  ffinish();
}

const char *get_conf_log_directory(conf_t *conf)
{
  fstart("conf: %p", conf);
  assert(conf != NULL);

  const char *ret;
  ret = conf->log_directory;

  ffinish("ret: %s", ret);
  return ret;
}

const char *get_conf_log_prefix(conf_t *conf)
{
  fstart("conf: %p", conf);
  assert(conf != NULL);

  const char *ret;
  ret = conf->log_prefix;

  ffinish("ret: %s", ret);
  return ret;
}

const char *get_conf_log_messages(conf_t *conf)
{
  fstart("conf: %p", conf);
  assert(conf != NULL);

  const char *ret;
  ret = conf->mname;

  ffinish("ret: %s", ret);
  return ret;
}

int get_conf_log_flags(conf_t *conf)
{
  fstart("conf: %p", conf);
  assert(conf != NULL);

  int ret;
  ret = conf->flags;

  ffinish("ret: %d", ret);
  return ret;
}

int get_conf_log_logging_enabled(conf_t *conf)
{
  fstart("conf: %p", conf);
  assert(conf != NULL);

  int ret;
  ret = conf->logging_enabled;

  ffinish("ret: %d", ret);
  return ret;
}

void set_conf_param_rule_filename(conf_t *conf, const char *rname)
{
  fstart("conf: %p, rname: %s", conf, rname);
  assert(conf != NULL);

  conf->rname = rname;

  ffinish();
}

void set_conf_param_input_filename(conf_t *conf, const char *iname)
{
  fstart("conf: %p, iname: %s", conf, iname);
  assert(conf != NULL);

  conf->iname = iname;

  ffinish();
}

void set_conf_param_handle_filename(conf_t *conf, const char *hname)
{
  fstart("conf: %p, hname: %s", conf, hname);
  assert(conf != NULL);

  conf->hname = hname;

  ffinish();
}

void set_conf_param_window_size(conf_t *conf, int wlen)
{
  fstart("conf: %p, wsize: %d", conf, wlen);
  assert(conf != NULL);

  conf->wlen = wlen;

  ffinish();
}

void set_conf_param_token_size(conf_t *conf, int rs)
{
  fstart("conf: %p, rs: %d", conf, rs);
  assert(conf != NULL);

  conf->rs = rs;

  ffinish();
}

void set_conf_param_enable_clustering(conf_t *conf)
{
  fstart("conf: %p", conf);
  assert(conf != NULL);

  conf->clustering_enabled = TRUE;

  ffinish();
}

void set_conf_param_num_of_clusters(conf_t *conf, int nc)
{
  fstart("conf: %p, nc: %d", conf, nc);
  assert(conf != NULL);
  assert(nc > 0);

  conf->num_of_clusters = nc;

  ffinish();
}

void set_conf_param_num_of_trees(conf_t *conf, int nt)
{
  fstart("conf: %p, nt: %d", conf, nt);
  assert(conf != NULL);
  assert(nt > 0);

  conf->num_of_trees = nt;

  ffinish();
}

void set_conf_param_max_num_of_fetched(conf_t *conf, int nf)
{
  fstart("conf: %p, nf: %d", conf, nf);
  assert(conf != NULL);
  assert(nf >= 0);

  conf->max_num_of_fetched = nf;

  ffinish();
}

void set_conf_exp_local_test(conf_t *conf)
{
  fstart("conf: %p", conf);
  assert(conf != NULL);

  conf->local_test = TRUE;

  ffinish();
}

void set_conf_exp_use_hardcoded_keys(conf_t *conf)
{
  fstart("conf: %p", conf);
  assert(conf != NULL);

  conf->use_hardcoded_keys = TRUE;

  ffinish();
}

void set_conf_exp_use_tree_updater(conf_t *conf)
{
  fstart("conf: %p", conf);
  assert(conf != NULL);

  conf->use_tree_updater = TRUE;

  ffinish();
}

void set_conf_exp_prev_num_of_entries(conf_t *conf, int entries)
{
  fstart("conf: %p, entries: %d", conf, entries);
  assert(conf != NULL);

  conf->prev_num_of_entries = entries;

  ffinish();
}

const char *get_conf_param_rule_filename(conf_t *conf)
{
  fstart("conf: %p", conf);
  assert(conf != NULL);

  const char *ret;
  ret = conf->rname;

  ffinish("ret: %s", ret);
  return ret;
}

const char *get_conf_param_input_filename(conf_t *conf)
{
  fstart("conf: %p", conf);
  assert(conf != NULL);

  const char *ret;
  ret = conf->iname;

  ffinish("ret: %s", ret);
  return ret;
}

const char *get_conf_param_handle_filename(conf_t *conf)
{
  fstart("conf: %p", conf);
  assert(conf != NULL);

  const char *ret;
  ret = conf->hname;

  ffinish("ret: %s", ret);
  return ret;
}

int get_conf_param_window_size(conf_t *conf)
{
  fstart("conf: %p", conf);
  assert(conf != NULL);

  int ret;
  ret = conf->wlen;

  ffinish("ret: %d", ret);
  return ret;
}

int get_conf_param_token_size(conf_t *conf)
{
  fstart("conf: %p", conf);
  assert(conf != NULL);

  int ret;
  ret = conf->rs;

  ffinish("ret: %d", ret);
  return ret;
}

int get_conf_param_clustering_enabled(conf_t *conf)
{
  fstart("conf: %p", conf);
  assert(conf != NULL);

  int ret;
  ret = conf->clustering_enabled;

  ffinish("ret: %d", ret);
  return ret;
}

int get_conf_param_num_of_clusters(conf_t *conf)
{
  fstart("conf: %p", conf);
  assert(conf != NULL);

  int ret;
  ret = conf->num_of_clusters;

  ffinish("ret: %d", ret);
  return ret;
}

int get_conf_param_num_of_trees(conf_t *conf)
{
  fstart("conf: %p", conf);
  assert(conf != NULL);

  int ret;
  ret = conf->num_of_trees;

  ffinish("ret: %d", ret);
  return ret;
}

int get_conf_param_max_num_of_fetched(conf_t *conf)
{
  fstart("conf: %p", conf);
  assert(conf != NULL);

  int ret;
  ret = conf->max_num_of_fetched;

  ffinish("ret: %d", ret);
  return ret;
}

int get_conf_exp_local_test(conf_t *conf)
{
  fstart("conf: %p", conf);
  assert(conf != NULL);

  int ret;
  ret = conf->local_test;

  ffinish("ret: %d", ret);
  return ret;
}

int get_conf_exp_use_hardcoded_keys(conf_t *conf)
{
  fstart("conf: %p", conf);
  assert(conf != NULL);

  int ret;
  ret = conf->use_hardcoded_keys;

  ffinish("ret: %d", ret);
  return ret;
}

int get_conf_exp_use_tree_updater(conf_t *conf)
{
  fstart("conf: %p", conf);
  assert(conf != NULL);

  int ret;
  ret = conf->use_tree_updater;

  ffinish("ret: %d", ret);
  return ret;
}

int get_conf_exp_prev_num_of_entries(conf_t *conf)
{
  fstart("conf: %p", conf);
  assert(conf != NULL);

  int ret;
  ret = conf->prev_num_of_entries;

  ffinish("ret: %d", ret);
  return ret;
}
