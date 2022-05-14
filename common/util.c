#include <debug.h>
#include <defines.h>
#include <util.h>
#include <assert.h>
#include <stdlib.h>
#include <string.h>

const char *rboolean(int ret)
{
  const char *rstr;

  if (ret == TRUE)
    rstr = "true";
  else if (ret == FALSE)
    rstr = "false";
  else
    rstr = "error";

  return rstr;
}

const char *rstring(int ret)
{
  const char *rstr;

  if (ret == SUCCESS)
    rstr = "success";
  else if (ret == FAILURE)
    rstr = "failure";
  else
    rstr = "error";

  return rstr;
}

char *int2addr(uint32_t ip, char *ret)
{
  ret[0] = ip & 0xff;
  ret[1] = (ip >> 8) & 0xff;
  ret[2] = (ip >> 16) & 0xff;
  ret[3] = (ip >> 24) & 0xff;
  ret[4] = '\0';

  return ret;
}

uint32_t addr2int(char *addr, int alen)
{
  assert(addr != NULL);
  assert(alen >= 4);

  uint32_t ret;
  ret = (addr[3] << 24) | (addr[2] << 16) | (addr[1] << 8) | addr[0];

  return ret;
}

uint32_t ip2int(uint8_t *ip)
{
  fstart("ip: %s", ip);
  uint32_t ret, tmp, idx;
  uint8_t addr[16] = {0, };
  uint8_t ipb[4] = {0, };
  uint8_t *token;

  ret = 0;
  idx = 3;
  memcpy(addr, ip, strlen(ip));
  token = strtok(addr, ".");

  while (token)
  {
    tmp = atoi(token);
    ipb[idx--] = tmp;
    token = strtok(NULL, ".");
  }

  for (idx=0; idx<4; idx++)
  {
    tmp = ipb[idx];
    ret |= (tmp << (8 * idx));
  }

  ffinish("ret: %u", ret);
  return ret;
}

int char_to_int(char *str, int slen, int base)
{
  assert(str != NULL);

  int i;
  int ret = 0;
  char ch;

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
  return ret;
}

int int_to_char(int num, uint8_t *str, int base)
{
  assert(str != NULL);

  int i, tmp, rem; 
  uint32_t ret;

  ret = 0;
  tmp = num;
  for (i=0; i<10; i++)
  {
    rem = tmp % base;
    if (rem > 0)
      ret = i;
    tmp /= base;
  }

  ret++;

  tmp = num;
  for (i=0; i<ret; i++)
  {
    rem = tmp % base;
    if (rem >= 0 && rem <= 9)
      str[ret - i - 1] = rem + 48;
    if (rem >= 10)
      str[ret - i - 1] = rem + 87;
    tmp /= base;
  }

  return ret;
}

uint16_t ip_checksum(uint8_t *iph, int len)
{
  fstart("iph: %p, len: %d", iph, len);
  uint16_t ret, tmp;
  uint32_t sum;
  int i;

  sum = 0;

  for (i=0; i<len; i+=2)
  {
    tmp = ((iph[i] & 0xff) << 8) | (iph[i+1] & 0xff);
    sum += tmp;
  }

  while (sum >> 16)
    sum = (sum & 0xffff) + (sum >> 16);

  sum = ~sum & 0x0000ffff;
  ret = sum;

  ffinish("ret: 0x%04x", ret);
  return ret;
}

uint16_t udp_checksum(uint8_t *iph, int iplen, uint8_t *udph, int udplen, 
    uint8_t *payload, int plen)
{
  fstart("iph: %p, iplen: %d, udph: %p, udplen: %d, payload: %p, plen: %d", iph, iplen, udph, udplen, payload, plen);
  uint16_t ret, tmp, tlen;
  uint32_t sum;
  uint8_t pseudo[BUF_SIZE] = {0, };
  uint8_t *p;
  int i, len;

  len = 20 + plen;
  tlen = udplen + plen;
  p = pseudo;

  pseudo[0] = iph[12];
  pseudo[1] = iph[13];
  pseudo[2] = iph[14];
  pseudo[3] = iph[15];

  pseudo[4] = iph[16];
  pseudo[5] = iph[17];
  pseudo[6] = iph[18];
  pseudo[7] = iph[19];

  pseudo[8] = 0;
  pseudo[9] = 17; 
  pseudo[10] = (tlen >> 8) & 0xff;
  pseudo[11] = tlen & 0xff;

  p += 12;
  memcpy(p, udph, udplen);

  p += udplen;
  memcpy(p, payload, plen);

  sum = 0;

  for (i=0; i<len; i=i+2)
  {
    tmp = ((pseudo[i] & 0xff) << 8) | (pseudo[i+1] & 0xff);
    sum += tmp;
  }

  while (sum >> 16)
    sum = (sum & 0xffff) + (sum >> 16);

  sum = ~sum & 0x0000ffff;
  ret = sum;

  ffinish("ret: 0x%04x", ret);
  return ret;
}
