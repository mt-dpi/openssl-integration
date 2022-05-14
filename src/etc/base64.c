#include <stdlib.h>
#include <string.h>

#include "base64.h"
#include "bit_op.h"
#include <dpi/debug.h>
#include <dpi/defines.h>

static uint8_t base64_url_table[64] = {
  'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H',
  'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P',
  'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X',
  'Y', 'Z', 'a', 'b', 'c', 'd', 'e', 'f',
  'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n',
  'o', 'p', 'q', 'r', 's', 't', 'u', 'v',
  'w', 'x', 'y', 'z', '0', '1', '2', '3',
  '4', '5', '6', '7', '8', '9', '-', '_',
};

int base64_url_encode(uint8_t *in, int ilen, uint8_t *out, int *olen)
{
  fstart("in: %p, ilen: %d, out: %p, olen: %p", in, ilen, out, olen);
  assert(in != NULL);
  assert(ilen > 0);
  assert(out != NULL);
  assert(olen != NULL);

  uint8_t *tmp;
  uint8_t bits[BUF_SIZE] = {0, };
  uint8_t *p;
  uint8_t byte;
  int i, ret, blen, before_bits_per_byte, after_bits_per_byte, idx, tlen, plen;

  ret = FAILURE;
  tmp = NULL;
  before_bits_per_byte = 8;
  after_bits_per_byte = 6;
  byte_to_bit(in, before_bits_per_byte, ilen, bits);
  //if (!bits) goto out;
  blen = ilen * before_bits_per_byte;
  
  if (blen % 24 != 0)
  {
    tlen = blen + (24 - blen % 24);
    tmp = (uint8_t *)calloc(tlen, sizeof(uint8_t));
    if (!tmp) goto out;
    memcpy(tmp, bits, blen);
    plen = (tlen - blen) / 8;
    //free(bits);
    //bits = NULL;
  }
  else
  {
    tmp = bits;
    tlen = blen;
  }

  dprint(DPI_DEBUG_CIRCUIT, "bits", tmp, 0, tlen, 16);
  idx = 0;

  for (p = tmp; p < tmp + blen; p += after_bits_per_byte)
  {
    byte = bit_to_byte(p, after_bits_per_byte, 0);
    out[idx++] = base64_url_table[byte];
  }

  for (i=0; i<plen; i++)
  {
    out[idx++] = '=';
  }

  *olen = tlen / after_bits_per_byte;

  ret = SUCCESS;
out:
  if (blen % 24 != 0 && tmp)
    free(tmp);
  ffinish("ret: %d", ret);
  return ret;
}

int base64_url_decode(uint8_t *in, int ilen, uint8_t *out, int *olen)
{
  fstart("in: %p, ilen: %d, out: %p, olen: %p", in, ilen, out, olen);
  assert(in != NULL);
  assert(ilen > 0);
  assert(out != NULL);
  assert(olen != NULL);

  uint8_t *tmp;
  uint8_t bits[BUF_SIZE] = {0, };
  int i, j, ret, blen, before_bits_per_byte, after_bits_per_byte, plen;

  // plen: padding length in bytes, tmp: temporary decoded base64 string
  ret = FAILURE;
  tmp = NULL;
  plen = 0;

  tmp = (uint8_t *)calloc(ilen, sizeof(uint8_t));
  if (!tmp) goto out;

  for (i=0; i<ilen; i++)
  {
    if (in[i] == '=')
    {
      tmp[i] = 0;
      plen++;
    }
    else
    {
      for (j=0; j<64; j++)
      {
        if (base64_url_table[j] == in[i])
          break;
      }
      tmp[i] = j;
    }
  }
  before_bits_per_byte = 6;
  after_bits_per_byte = 8;
  byte_to_bit(tmp, before_bits_per_byte, ilen, bits);
  //if (!bits) goto out;
  blen = ilen * before_bits_per_byte;
  dprint(DPI_DEBUG_CIRCUIT, "bits", bits, 0, blen, 16);
  *olen = blen / after_bits_per_byte - plen;
  
  for (i=0; i<*olen; i++)
    out[i] = bit_to_byte(bits, after_bits_per_byte, after_bits_per_byte*i);

  ret = SUCCESS;
out:
  if (tmp)
    free(tmp);
  //if (bits)
    //free(bits);
  ffinish("ret: %d", ret);
  return ret;
}
