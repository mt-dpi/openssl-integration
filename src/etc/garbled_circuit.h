#ifndef __GARBLED_CIRCUIT_H__
#define __GARBLED_CIRCUIT_H__

#include <stdint.h>
#include <dpi/fernet.h>

#define GARBLED_GATE_TYPE_XOR             0
#define GARBLED_GATE_TYPE_AND             1
#define GARBLED_GATE_TYPE_INV             2
#define GARBLED_GATE_TYPE_EQ              3
#define GARBLED_GATE_TYPE_EQW             4
#define GARBLED_GATE_TYPE_MAND            5

#define GARBLED_GATE_INPUT_WIRE           0
#define GARBLED_GATE_OUTPUT_WIRE          1

#define GARBLED_CIRCUIT_BRISTOL_AES_128   0
#define GARBLED_CIRCUIT_BRISTOL_AES_192   1
#define GARBLED_CIRCUIT_BRISTOL_AES_256   2
#define GARBLED_CIRCUIT_TEST_1            3
#define GARBLED_CIRCUIT_TEST_2            4

#define GARBLED_CIRCUIT_GARBLER           0
#define GARBLED_CIRCUIT_EVALUATOR         1

#define MAX_NEXT_GATES                    512

typedef struct gc_gate_st
{
  int id;
  uint8_t type;         // gate type
  uint16_t inum;        // # of gate inputs
  uint16_t iset;        // # of set inputs (it should be identical to inum finally)
  uint16_t *inputs;     // wire input indexes
  uint8_t **ikeys;      // wire key values
  int *iklens;          // wire key length
  uint8_t *ivalues;     // wire input values
  uint8_t *enabled;     // wire inputs enabled
  uint16_t onum;        // # of gate outputs
  uint16_t oset;        // # of set outputs
  uint16_t *outputs;    // wire output indexes
  uint16_t nnum;        // # of next gates
  uint16_t *nexts;      // next gates
  uint8_t *table[2][2]; // garbled table
  uint16_t emlen[2][2];      // encrypted message length of each entry of the garbled table
} gc_gate_t;

typedef struct gc_wire_st {
  int id;
  uint8_t pbit;
  uint8_t enabled;
  uint8_t keys[2][FERNET_ENCODED_KEY_BYTES];
  int klens[2];
  uint8_t value;
  uint16_t nnum;      // # of next gates
  uint16_t nexts[MAX_NEXT_GATES];    // next gates
} gc_wire_t;

typedef struct gc_gateq_entry_st {
  gc_gate_t *gate;
  struct gc_gateq_entry_st *prev;
  struct gc_gateq_entry_st *next;
} gc_gateq_entry_t;

typedef struct gc_gateq_st {
  int num;
  gc_gateq_entry_t *start;
  gc_gateq_entry_t *end;
} gc_gateq_t;

typedef struct garbled_circuit_st
{
  int type;                           // circuit type
  int role;
  int gnum;                           // # of gates
  gc_gate_t **gates;     // gate array
  int wnum;                           // # of wires
  gc_wire_t **wires;     // wire array
  uint8_t inum;                       // # of circuit inputs
  uint8_t iset;                       // # of set circuit inputs
  uint16_t **ilens;                     // circuit input lengths
  uint8_t ***inputs;                   // circuit inputs (key, plaintext)
  uint8_t onum;                       // # of circuit outputs
  uint16_t *olens;                     // circuit output lengths (in bits)
  uint8_t **obits;                    // circuit outputs (ciphertext in bits)
  uint8_t **obytes;                   // circuit outputs (ciphertext in bytes)
} garbled_circuit_t;

garbled_circuit_t *init_garbled_circuit(const char *cname, int role);
void add_gc_input(garbled_circuit_t *gc, uint8_t *input, int ilen);
void prepare_gc_operation(garbled_circuit_t *gc);
int evaluate_garbled_circuit(garbled_circuit_t *gc);
int get_gc_num_of_outputs(garbled_circuit_t *gc);
uint8_t *get_gc_output_bits(garbled_circuit_t *gc, int idx, int *olen);
uint8_t *get_gc_output_bytes(garbled_circuit_t *gc, int idx, int *olen);
void free_garbled_circuit(garbled_circuit_t *gc);

int garbled_circuit_encrypt(garbled_circuit_t *gc, uint8_t *in, int ilen, 
    uint8_t *out, int *olen);
int garbled_circuit_decrypt(garbled_circuit_t *gc, uint8_t *in, int ilen,
    uint8_t *out, int *olen);

gc_gate_t *init_gc_gate(int id, uint16_t inum, uint16_t onum);
void add_gc_type(gc_gate_t *gate, uint8_t type);
void add_gc_wire(gc_gate_t *gate, uint16_t widx, uint8_t is_output);
void add_gc_next_gates(gc_wire_t *gate, int nnum, int *nexts);
void free_gc_gate(gc_gate_t *gate);

gc_wire_t *init_gc_wire(int id, int role);
void free_gc_wire(gc_wire_t *wire);

#endif /* __GARBLED_CIRCUIT_H__ */
