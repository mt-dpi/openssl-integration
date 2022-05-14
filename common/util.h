#ifndef __UTIL_H__
#define __UTIL_H__

#include <stdint.h>

const char *rboolean(int ret);
const char *rstring(int ret);
char *int2addr(uint32_t ip, char *ipb);
uint32_t addr2int(char *addr, int alen);
uint32_t ip2int(uint8_t *ip);
int char_to_int(char *str, int slen, int base);
int int_to_char(int num, uint8_t *str, int base);

uint16_t ip_checksum(uint8_t *iph, int len);
uint16_t udp_checksum(uint8_t *iph, int iplen, uint8_t *udph, int udplen,
    uint8_t *payload, int plen);

static char ipb[5];
#endif /* __UTIL_H__ */
