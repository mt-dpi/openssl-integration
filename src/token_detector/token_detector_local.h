#ifndef __TOKEN_DETECTOR_LOCAL_H__
#define __TOKEN_DETECTOR_LOCAL_H__

#include "../etc/token.h"
#include "token_detector.h"

struct token_detector_st
{
  int (*token_detection)(dpi_t *dpi, etoken_t *etoken);
};

#endif /* __TOKEN_DETECTOR_LOCAL_H__ */
