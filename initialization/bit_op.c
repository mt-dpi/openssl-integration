#include <stdio.h>
#include <stdint.h>
#include <assert.h>
#include <stdlib.h>

uint8_t bit_to_byte(uint8_t *a, int addr)
{
  uint8_t ret;
  int i, last;
  ret = 0;

  for (i=0; i<8; i++)
    ret = ret * 2 + a[i+addr];

  return ret;
}

uint8_t *byte_to_bit(uint8_t *b, int len)
{
  uint8_t *ret;
  int i, j, val;
  ret = (uint8_t *)malloc(8 * len);

  for (i=0; i<len; i++)
  {
    val = b[i];
    for (j=0; j<8; j++)
    {
      ret[8*(i+1)-j-1] = val % 2;
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


int main()
{
  int a, b, i;
  uint8_t tmp1[16] = {1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1};
  uint8_t tmp2[2] = {5, 65};
  uint8_t *ret;

  a = 0;
  b = 1;
  printf("a = %d, b = %d, a xor b = %d\n", a, b, xor(a, b));

  a = 1;
  b = 1;
  printf("a = %d, b = %d, a xor b = %d\n", a, b, xor(a, b));

  a = 0;
  b = 0;
  printf("a = %d, b = %d, a and b = %d\n", a, b, and(a, b));

  a = 1;
  b = 1;
  printf("a = %d, b = %d, a and b = %d\n", a, b, and(a, b));

  a = 0;
  printf("a = %d, inv a = %d\n", a, inv(a));

  for (i=0; i<2; i++)
  {
    printf("%d byte: %02x\n", i, bit_to_byte(tmp1, 8*i));
  }

  ret = byte_to_bit(tmp2, 2);
  for (i=0; i<16; i++)
  {
    printf("%02x ", ret[i]);
  }
  printf("\n");

  return 0;
}
