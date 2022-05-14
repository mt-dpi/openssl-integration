#include <dpi/dpi.h>
#include <dpi/debug.h>
#include <stdlib.h>
#include <stdio.h>
#include <getopt.h>
#include <string.h>
#include <unistd.h>

#include <linux/perf_event.h>
#include <sys/ioctl.h>
#include <sys/syscall.h>

#include "../etc/counter_table.h"
#include "../etc/token.h"
#include "../util/params.h"

#define COUNT 5000
#define COUNTD 5000.0

#define print_interval(m, a, b) \
  printf("%s: %lu ns\n", m, b - a);

unsigned long get_current_time(void)
{
  struct timespec ts;
  clock_gettime(CLOCK_MONOTONIC, &ts);
  return ts.tv_sec * 1000000000 + ts.tv_nsec;
}

static long perf_event_open(struct perf_event_attr *hw_event, pid_t pid,
    int cpu, int group_fd, unsigned long flags)
{
  int ret;
  ret = syscall(__NR_perf_event_open, hw_event, pid, cpu, group_fd, flags);
  return ret;
}

int main(int argc, char *argv[])
{
  dpi_t *dpi;
  struct perf_event_attr pe1, pe2;
  conf_t *conf;
  param_t *params;
  counter_table_t *table;
  int i, fd1, fd2, fsize, cvalue;
  token_t *token;
  uint8_t *buf;
  unsigned long start, end;
  uint16_t wsize, bsize;
  long long count1, count2;
  const char *iname;
  FILE *fp;
  entry_t *entry;

  memset(&pe1, 0, sizeof(struct perf_event_attr));
  pe1.type = PERF_TYPE_HW_CACHE;
  pe1.size = sizeof(struct perf_event_attr);
  pe1.config = PERF_COUNT_HW_CACHE_L1D | PERF_COUNT_HW_CACHE_OP_READ << 8 
    | PERF_COUNT_HW_CACHE_RESULT_MISS << 16;
  pe1.disabled = 1;
  pe1.exclude_kernel = 1;
  pe1.exclude_hv = 1;

  fd1 = perf_event_open(&pe1, 0, -1, -1, 0);
  if (fd1 < 0)
  {
    fprintf(stderr, "Error opening leader %llx\n", pe1.config);
    exit(EXIT_FAILURE);
  }

  memset(&pe2, 0, sizeof(struct perf_event_attr));
  pe2.type = PERF_TYPE_HW_CACHE;
  pe2.size = sizeof(struct perf_event_attr);
  pe2.config = PERF_COUNT_HW_CACHE_LL | PERF_COUNT_HW_CACHE_OP_READ << 8 
    | PERF_COUNT_HW_CACHE_RESULT_MISS << 16;
  pe2.disabled = 1;
  pe2.exclude_kernel = 1;
  pe2.exclude_hv = 1;

  fd2 = perf_event_open(&pe2, 0, -1, -1, 0);
  if (fd2 < 0)
  {
    fprintf(stderr, "Error opening leader %llx\n", pe2.config);
    exit(EXIT_FAILURE);
  }

  conf = init_conf_module();
  set_conf_module(conf, argc, argv);
  dpi = init_dpi_context(DPI_ROLE_MIDDLEBOX, conf);
  params = init_params(conf);
  table = init_counter_table(params);
  iname = get_param_input_filename(params);
  wsize = params->wlen;
  bsize = 16;

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
    fread(buf, 1, fsize, fp);

    fclose(fp);
  }

  dpi_add_message(dpi, buf, fsize);

  ioctl(fd1, PERF_EVENT_IOC_RESET, 0);
  ioctl(fd2, PERF_EVENT_IOC_RESET, 0);
  ioctl(fd1, PERF_EVENT_IOC_ENABLE, 0);
  ioctl(fd2, PERF_EVENT_IOC_ENABLE, 0);

  for (i=0; i<1000; i++)
  {
    token = dpi_get_next_token(dpi);
    cvalue = get_counter_table_cvalue(table, 0);
  }

  ioctl(fd1, PERF_EVENT_IOC_DISABLE, 0);
  ioctl(fd2, PERF_EVENT_IOC_DISABLE, 0);
  read(fd1, &count1, sizeof(long long));
  read(fd2, &count2, sizeof(long long));

  printf("L1 Data Cache Miss: %lld\n", count1);
  printf("LL Cache Miss: %lld\n", count2);
 
  close(fd1);
  close(fd2);
  free_counter_table(table);
  free_dpi_context(dpi);
  return 0;
}
