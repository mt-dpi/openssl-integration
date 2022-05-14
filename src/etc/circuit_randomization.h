#ifndef __CIRCUIT_RANDOMIZATION_H__
#define __CIRCUIT_RANDOMIZATION_H__

#define CIRCUIT_TYPE_AES  1

#define GATE_TYPE_AND 0
#define GATE_TYPE_XOR 1

#include <stdint.h>
#include <dpi/circuit.h>

typedef struct mb_input_st
{
  uint8_t *pkey;      // fixed, publicly known AES key
  int plen;           // len(pkey)
  uint8_t *cert;      // certificate
  int clen;           // len(cert)
  uint8_t *keyword;   // keyword
  int klen;           // len(keyword)
  uint8_t *random;    // random
  int rlen;           // len(random)
  int cid;
} mb_input_t;

typedef struct sender_input_st
{
  const char *cname;  // circuit
  uint8_t *pkey;      // fixed, publicly known AES key
  int plen;           // len(pkey)
  uint8_t *cert;      // certificate
  int clen;           // len(cert)
  uint8_t *skey;       // handle generation key
  int slen;           // len(key)
  int cid;
} sender_input_t;

int fernet_random_ot(int role, int sock, uint8_t *a, uint8_t *b, uint8_t *c);
int generate_certificate(uint8_t *keyword, int klen, uint8_t *pkey, 
    uint8_t *random, int rlen, uint8_t *cert, int *clen);
int circuit_randomization(int role, int sock, uint8_t a, uint8_t b, uint8_t c, void *data);

#endif /* __CIRCUIT_H__ */
