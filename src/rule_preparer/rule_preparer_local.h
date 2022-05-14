#ifndef __RULE_PREPARER_LOCAL_H__
#define __RULE_PREPARER_LOCAL_H__

#include "rule_preparer.h"
#include "../etc/token.h"

struct rule_preparer_st
{
  int (*rule_preparation)(dpi_t *dpi);
};

#endif /* __RULE_PREPARER_LOCAL_H__ */
