#ifndef __DPI_LOGGER_H__
#define __DPI_LOGGER_H__

#include <dpi/logger.h>
#include "dpi_names.h"
#include "dpi_flags.h"

#define dpi_print_interval(m, a, b) \
  printf("%s: %lu ns\n", m, b - a);

int dpi_add(logger_t *logger, int name);
int dpi_move(logger_t *logger, int from, int to);
int dpi_interval(logger_t *logger, int start, int end);
int dpi_print(logger_t *logger, int name, int flags);
int dpi_print_all(logger_t *logger);
unsigned long dpi_get_current_time(void);
unsigned long dpi_get_current_cpu(void);

#endif /* __DPI_LOGGER_H__ */
