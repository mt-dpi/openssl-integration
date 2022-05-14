#ifndef __CIRCUIT_H__
#define __CIRCUIT_H__

#include <stdint.h>

#define MPC_GATE_TYPE_XOR                 0
#define MPC_GATE_TYPE_AND                 1
#define MPC_GATE_TYPE_INV                 2
#define MPC_GATE_TYPE_EQ                  3
#define MPC_GATE_TYPE_EQW                 4
#define MPC_GATE_TYPE_MAND                5

#define MPC_GATE_INPUT_WIRE               0
#define MPC_GATE_OUTPUT_WIRE              1

#define MPC_CIRCUIT_BRISTOL_AES_128       0
#define MPC_CIRCUIT_BRISTOL_AES_192       1
#define MPC_CIRCUIT_BRISTOL_AES_256       2
#define MPC_CIRCUIT_TEST_1                3
#define MPC_CIRCUIT_TEST_2                4
#define MPC_CIRCUIT_TEST_3                5

#define MPC_CIRCUIT_RANDOMIZATION_NONE    0
#define MPC_CIRCUIT_RANDOMIZATION_FLIP    1

#define MAX_NEXT_GATES                    512

typedef struct gate_st {
  int id;
  uint8_t type;       // gate type
  uint16_t inum;      // # of gate inputs
  uint16_t iset;      // # of set inputs (it should be identical to inum finally)
  uint16_t *inputs;   // wire input indexes
  uint8_t *ivalues;   // wire input values
  uint8_t *enabled;   // wire inputs enabled
  uint16_t onum;      // # of gate outputs
  uint16_t oset;      // # of set outputs
  uint16_t *outputs;  // wire output indexes
  uint16_t nnum;      // # of next gates
  uint16_t *nexts;    // next gates
} gate_t;

typedef struct wire_st {
  int id;
  uint8_t enabled;
  uint8_t value;
  uint16_t nnum;      // # of next gates
  uint16_t nexts[MAX_NEXT_GATES];    // next gates
} wire_t;

typedef struct gateq_entry_st {
  gate_t *gate;
  struct gateq_entry_st *prev;
  struct gateq_entry_st *next;
} gateq_entry_t;

typedef struct gateq_st {
  int num;
  gateq_entry_t *start;
  gateq_entry_t *end;
} gateq_t;

typedef struct circuit_st {
  int type;           // circuit type
  int gnum;           // # of gates
  gate_t **gates;     // gate array
  int wnum;           // # of wires
  wire_t **wires;     // wire array
  uint8_t inum;       // # of circuit inputs
  uint8_t iset;       // # of set circuit inputs
  uint8_t *ilens;     // circuit input lengths
  uint8_t **inputs;   // circuit inputs (key, plaintext)
  uint8_t onum;       // # of circuit outputs
  uint8_t *olens;     // circuit output lengths (in bits)
  uint8_t **obits;    // circuit outputs (ciphertext in bits)
  uint8_t **obytes;   // circuit outputs (ciphertext in bytes)
  gateq_t *gateq;     // queue of gates to be processed
  int role;
} circuit_t;

circuit_t *init_circuit(const char *cname);
void add_input(circuit_t *circuit, uint8_t *input, int ilen);
void change_input(circuit_t *circuit, int idx, uint8_t *input, int ilen);
void prepare_circuit_operation(circuit_t *circuit);
void proceed(circuit_t *circuit);
void proceed_one_depth(circuit_t *circuit);
void proceed_full_depths(circuit_t *circuit);
int get_num_of_outputs(circuit_t *circuit);
uint8_t *get_output_bits(circuit_t *circuit, int idx, int *olen);
uint8_t *get_output_bytes(circuit_t *circuit, int idx, int *olen);
void free_circuit(circuit_t *circuit);
int get_circuit_type(circuit_t *circuit);
void set_circuit_role(circuit_t *circuit, int role);

gate_t *init_gate(int id, uint16_t inum, uint16_t onum);
void add_type(gate_t *gate, uint8_t type);
void add_wire(gate_t *gate, uint16_t widx, uint8_t is_output);
//void add_next_gates(gate_t *gate, int nnum, int *nexts);
void add_next_gates(wire_t *gate, int nnum, int *nexts);
void free_gate(gate_t *gate);

void enqueue(circuit_t *circuit, gate_t *gate);
gate_t *dequeue(circuit_t *circuit, int only_not_and, int check);

wire_t *init_wire(int id);
void set_wire_value(circuit_t *circuit, int idx, int value);
int get_wire_value(circuit_t *circuit, int idx);
void free_wire(wire_t *wire);

#endif /* __CIRCUIT_H__ */
