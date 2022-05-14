#ifndef __CIRCUIT_H__
#define __CIRCUIT_H__

#define CIRCUIT_TYPE_AES  1

#define GATE_TYPE_AND 0
#define GATE_TYPE_XOR 1

#include <stdint.h>

int fernet_random_ot(int role, int sock, uint8_t *a, uint8_t *b, uint8_t *c);
int generate_certificate(uint8_t *keyword, int klen, uint8_t *pkey, 
    uint8_t *random, int rlen, uint8_t *cert, int *clen);
int circuit_randomization(int role, int sock, int circuit, 
    uint8_t a, uint8_t b, uint8_t c, uint8_t *cert, int clen, 
    uint8_t *random, int rlen, uint8_t *keyword, int klen);

#endif /* __CIRCUIT_H__ */
