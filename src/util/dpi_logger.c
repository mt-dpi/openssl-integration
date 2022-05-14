#include "dpi_logger.h"
#include <sys/time.h>
#include <dpi/setting.h>
#include <dpi/defines.h>
#include <dpi/debug.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdio.h>
#include <assert.h>

static logger_ops_t gops = 
{
  .add = dpi_add,
  .move = dpi_move,
  .interval = dpi_interval,
  .print = dpi_print,
  .print_all = dpi_print_all,
};

void
init_names(logger_t *logger, const char *msgs);

logger_t *
init_logger(const char *log_directory, const char *log_prefix, 
    const char *msgs, int flags)
{
  fstart("log_directory: %s, log_prefix: %s, msgs: %s, flags: %d", log_directory, log_prefix, msgs, flags);
  logger_t *ret;
  ret = (logger_t *)calloc(1, sizeof(logger_t));

  ret->log_prefix = (char *)calloc(1, strlen(log_prefix)+1);
  memcpy(ret->log_prefix, log_prefix, strlen(log_prefix));
  ret->log_directory = log_directory;
  ret->ops = &gops;
  ret->flags = flags;
  init_names(ret, msgs);
  set_time_func(ret, dpi_get_current_time);
  set_cpu_func(ret, dpi_get_current_cpu);

  ffinish("ret: %p", ret);
  return ret;
}

void 
init_names(logger_t *logger, const char *msgs)
{
  fstart("logger: %p, msgs: %s", logger, msgs);
  assert(logger != NULL);

  FILE *fp;
  char buf[LBUF_SIZE] = {0};
  char *ptr, *tmp, *name;
  int val, len;

  if (access(msgs, F_OK) == -1)
  {
    emsg("File not exists: %s", msgs);
    abort();
  }

  fp = fopen(msgs, "r");
  
  if (!fp)
    emsg("Cannot open the file: %s", msgs);

  while (feof(fp) == 0)
  {
    memset(buf, 0x0, LBUF_SIZE);
    fgets(buf, LBUF_SIZE, fp);
    ptr = strtok(buf, " ");

    if (!ptr)
      continue;

    if (ptr[0] != '#')
      continue;

    // name
    name = NULL;
    ptr = strtok(NULL, " ");

    if (!ptr)
      continue;

    tmp = strstr(ptr, "DPI");
    if (!tmp)
      continue;

    len = strlen(ptr);
    name = (char *)calloc(1, len+1);
    memcpy(name, ptr, len);

    if (!strncmp(name, "__DPI_NAMES_H__", 15))
      continue;

    // value
    ptr = strtok(NULL, " ");
    len = strlen(ptr);
    if (ptr[len-1] == '\n')
      ptr[len-1] = 0;
    val = atoi(ptr);

    logger->name[val] = name;
    dmsg(DPI_DEBUG_MIDDLEBOX, "logger->name[%d] = %s", val, name);
  }

  fclose(fp);

  ffinish();
}

void 
fin_logger(logger_t *logger)
{
  fstart("logger: %p", logger);
  assert(logger != NULL);

  unsigned char log_cpu_file_name[MAX_FILE_NAME_LEN] = {0, };
  unsigned char log_time_file_name[MAX_FILE_NAME_LEN] = {0, };
  int et;
  FILE *cfp, *tfp;
  int i, flags;

  flags = logger->flags;
  et = logger->time_func();

  if (flags & DPI_LF_CPU)
  {
    snprintf((char *) log_cpu_file_name, MAX_FILE_NAME_LEN, "%s/%s_cpu_%u.csv",
        logger->log_directory, logger->log_prefix, et);
    cfp = fopen((const char *)log_cpu_file_name, "w");
    for (i=0; i<NUM_OF_LOGS; i++)
    {
      if (logger->log[i].cpu > 0)
      {
        fprintf(cfp, "%d, %s, %lu\n", i, logger->name[i], logger->log[i].cpu);
      }
    }
    fclose(cfp);
  }

  if (flags & DPI_LF_TIME)
  {
    snprintf((char *) log_time_file_name, MAX_FILE_NAME_LEN, "%s/%s_time_%u.csv",
        logger->log_directory, logger->log_prefix, et);
    tfp = fopen((const char *)log_time_file_name, "w");
    for (i=0; i<NUM_OF_LOGS; i++)
    {
      if (logger->log[i].time > 0)
      {
        fprintf(tfp, "%d, %s, %lu\n", i, logger->name[i], logger->log[i].time);
      }
    }
    fclose(tfp);
  }

  if (logger->log_prefix)
  {
    free(logger->log_prefix);
    logger->log_prefix = NULL;
  }

  if (logger->name)
  {
    for (i=0; i < NUM_OF_LOGS; i++)
    {
      if (logger->name[i])
      {
        free(logger->name[i]);
        logger->name[i] = NULL;
      }
    }
  }

  free(logger);
  ffinish();
}

void
set_time_func(logger_t *logger, unsigned long (*time_func)(void))
{
  fstart("logger: %p, time_func: %p", logger, time_func);

  logger->time_func = time_func;

  ffinish();
}

void
set_cpu_func(logger_t *logger, unsigned long (*cpu_func)(void))
{
  fstart("logger: %p, cpu_func: %p", logger, cpu_func);

  logger->cpu_func = cpu_func;

  ffinish();
}

int 
dpi_add(logger_t *logger, int name)
{
  fstart("logger: %p, name: %s", logger, logger->name[name]);
  assert(logger != NULL);
  assert(name >= 0);
  
  int flags;

  flags = logger->flags;

  if (flags & DPI_LF_CPU)
  {
    if (logger->cpu_func)
      logger->log[name].cpu = logger->cpu_func();
  }

  if (flags & DPI_LF_TIME)
  {
    if (logger->time_func)
      logger->log[name].time = logger->time_func();
  }

  ffinish();
  return SUCCESS;
}

int
dpi_move(logger_t *logger, int from, int to)
{
  fstart("logger: %p, from: %s, to: %s", logger, logger->name[from], logger->name[to]);

  logger->log[to].cpu = logger->log[from].cpu;
  logger->log[to].time = logger->log[from].time;

  ffinish();
  return SUCCESS;
}

int 
dpi_interval(logger_t *logger, int start, int end)
{
  fstart("logger: %p, start: %s, end: %s", logger, logger->name[start], logger->name[end]);
  assert(logger != NULL);
  assert(start >= 0);
  assert(end > start);

  int flags, ret;

  const char *nstart;
  const char *nend;

  unsigned long cstart;
  unsigned long cend;
  unsigned long tstart;
  unsigned long tend;

  flags = logger->flags;
  ret = 0;

  nstart = logger->name[start];
  nend = logger->name[end];

  cstart = logger->log[start].cpu;
  cend = logger->log[end].cpu;
  tstart = logger->log[start].time;
  tend = logger->log[end].time;

  if (flags & DPI_LF_CPU)
  {
    printf("cpu) from %s to %s: %lu ms\n", nstart, nend, cend - cstart); 
  }

  if (flags & DPI_LF_TIME)
  {
    printf("time) from %s to %s: %lu ms\n", nstart, nend, tend - tstart);
    ret = tend - tstart;
  }

  ffinish();
  return SUCCESS;
}

int
dpi_print(logger_t *logger, int name, int flags)
{
  fstart("logger: %p, name: %s", logger, logger->name[name]);
  assert(logger != NULL);
  assert(name >= 0);
  assert(flags >= 0);
  
  if (flags & DPI_LF_CPU)
  {
    printf("cpu) at %s: %lu ms\n", logger->name[name], logger->log[name].cpu);
  }

  if (flags & DPI_LF_TIME)
  {
    printf("time) at %s: %lu ms\n", logger->name[name], logger->log[name].time);
  }

  ffinish();
  return SUCCESS;
}

int 
dpi_print_all(logger_t *logger)
{
  fstart("logger: %p", logger);
  assert(logger != NULL);

  int i, flags;
  flags = logger->flags;

  if (flags & DPI_LF_CPU)
  {
    for (i=0; i<NUM_OF_LOGS; i++)
    {
      if (logger->log[i].cpu > 0)
      {
        dpi_print(logger, i, DPI_LF_CPU);
      }
    }
  }

  if (flags & DPI_LF_TIME)
  {
    for (i=0; i<NUM_OF_LOGS; i++)
    {
      if (logger->log[i].time > 0)
      {
        dpi_print(logger, i, DPI_LF_TIME);
      }
    }
  }

  ffinish();
  return SUCCESS;
}

unsigned long dpi_get_current_time(void)
{
  fstart();
  unsigned long ret;
  struct timespec ts;

  //clock_gettime(CLOCK_MONOTONIC_COARSE, &ts);
  clock_gettime(CLOCK_MONOTONIC, &ts);
  ret = ts.tv_sec * 1000000000 + ts.tv_nsec;

  ffinish("ret: %lu", ret);
  return ret;
}

unsigned long dpi_get_current_cpu(void)
{
  fstart();
  unsigned long ret;
  struct timespec tp;

  clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &tp);
  ret = tp.tv_sec * 1000000+ tp.tv_nsec / 1000;

  ffinish("ret: %lu", ret);
  return ret;
}
