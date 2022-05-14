#ifndef __BIT_OP_H__
#define __BIT_OP_H__

#include <stdint.h>

uint8_t bit_to_byte(uint8_t *a, int bits_per_byte, int addr);
void byte_to_bit(uint8_t *b, int bits_per_byte, int len, uint8_t *ret);
uint8_t xor(uint8_t a, uint8_t b);
uint8_t and(uint8_t a, uint8_t b);
uint8_t inv(uint8_t a);
int char_to_int(uint8_t *str, uint32_t slen, int base);

#endif /*__BIT_OP_H__ */
