#include <stdio.h>
#include <stdint.h>
#include <assert.h>
#include <stdlib.h>
#include <dpi/debug.h>

uint8_t bit_to_byte(uint8_t *a, int bits_per_byte, int addr)
{
  uint8_t ret;
  int i, last;
  ret = 0;

  for (i=0; i<bits_per_byte; i++)
    ret = ret * 2 + a[i+addr];

  return ret;
}

void byte_to_bit(uint8_t *b, int bits_per_byte, int len, uint8_t *ret)
{
  int i, j, val;

  for (i=0; i<len; i++)
  {
    val = b[i];
    for (j=0; j<bits_per_byte; j++)
    {
      ret[bits_per_byte*(i+1)-j-1] = val % 2;
      val = val / 2;
    }
  }

  return ret;
}

uint8_t xor(uint8_t a, uint8_t b)
{
  assert(a == 0 || a == 1);
  assert(b == 0 || b == 1);
  return a == b? 0 : 1;
}

uint8_t and(uint8_t a, uint8_t b)
{
  assert(a == 0 || a == 1);
  assert(b == 0 || b == 1);
  return a * b;
}

uint8_t inv(uint8_t a)
{
  assert(a == 0 || a == 1);
  return a == 1? 0 : 1;
}

int char_to_int(uint8_t *str, uint32_t slen, int base)
{
  fstart("str: %s, slen: %d", str, slen);
  assert(str != NULL);

  int i;
  int ret = 0;
  uint8_t ch;

  if (!slen) goto out;

  for (i=0; i<slen; i++)
  {
    ch = str[i];
    if (ch == ' ')
      break;

    switch(ch)
    {
      case '0':
        ret *= base;
        break;
      case '1':
        ret = ret * base + 1;
        break;
      case '2':
        ret = ret * base + 2;
        break;
      case '3':
        ret = ret * base + 3;
        break;
      case '4':
        ret = ret * base + 4;
        break;
      case '5':
        ret = ret * base + 5;
        break;
      case '6':
        ret = ret * base + 6;
        break;
      case '7':
        ret = ret * base + 7;
        break;
      case '8':
        ret = ret * base + 8;
        break;
      case '9':
        ret = ret * base + 9;
        break;
      case 'a':
        ret = ret * base + 10;
        break;
      case 'b':
        ret = ret * base + 11;
        break;
      case 'c':
        ret = ret * base + 12;
        break;
      case 'd':
        ret = ret * base + 13;
        break;
      case 'e':
        ret = ret * base + 14;
        break;
      case 'f':
        ret = ret * base + 15;
        break;
      default:
        break;
    }
  }

out:
  ffinish("ret: %d", ret);
  return ret;
}

