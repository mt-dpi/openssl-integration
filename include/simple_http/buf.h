/**
 * @file buf.h
 * @author Hyunwoo Lee
 * @date 1 Nov 2018
 * @brief This file is to define the buffer operation
 */

#ifndef __BUF_H__
#define __BUF_H__

#include <stdlib.h>
#include <assert.h>
#include <stdio.h>
#include <stdint.h>

typedef struct buf_st
{
  uint8_t *data;
  int offset;
  int max;
} buf_t;

buf_t *init_alloc_buf_mem(buf_t **buf, int len);
buf_t *init_memcpy_buf_mem(buf_t *buf, uint8_t *data, int len);
buf_t *init_buf_mem(buf_t *buf, uint8_t *data, int len);
int update_buf_mem(buf_t *buf, uint8_t *data, int len);
int add_buf_char(buf_t *buf, uint8_t ch);
int get_buf_remaining(buf_t *buf);
uint8_t *get_buf_data(buf_t *buf);
uint8_t *get_buf_curr(buf_t *buf);
uint8_t *get_buf_end(buf_t *buf);
int get_buf_offset(buf_t *buf);
int get_buf_total(buf_t *buf);
void free_buf(buf_t *buf);

uint8_t *delete_space(uint8_t *p);
uint8_t *get_next_token(buf_t *buf, char *ch, int *len);


#endif /* __BUF_H__ */
