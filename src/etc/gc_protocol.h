#ifndef __GC_PROTOCOL_H__
#define __GC_PROTOCOL_H__

#include <dpi/debug.h>
#include <dpi/defines.h>
#include <dpi/garbled_circuit.h>
#include <dpi/oblivious_transfer.h>

// GC Garbler
int send_garbled_circuit_info(int sock, garbled_circuit_t *gc);
int receive_confirmation(int sock);
int send_encrypted_input_and_keys(int sock, garbled_circuit_t *gc, ot_t *ot, 
    uint8_t *input, int ilen);
int receive_result(int sock, garbled_circuit_t *gc, ot_t *ot);

// GC Evaluator
garbled_circuit_t *receive_garbled_circuit_info(int sock);
int send_confirmation(int sock);
int receive_encrypted_input_and_keys(int sock, garbled_circuit_t *gc, ot_t *ot,
    uint8_t *input, int ilen);
int send_result(int sock, garbled_circuit_t *gc, ot_t *ot);

#endif /* __GC_PROTOCOL_H__ */
