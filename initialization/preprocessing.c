#include <stdio.h>
#include <stdlib.h>

#include "aes_expanded.h"

#define GATE_TYPE_AND 0
#define GATE_TYPE_XOR 1
#define GATE_TYPE_INV 2

typedef struct gate_st 
{
  int id;
  int type;
  int input1;
  int input2;
  int output;
  struct gate_st *next;
} gate_t;

typedef struct circuit_st
{
  int num;
  gate_t *head;
} circuit_t;

typedef struct layer_st
{
  int id;
  int num;
  int idlst[1000];
  struct layer_st *next;
} layer_t;

circuit_t *init_circuit(void);
layer_t *init_layer(int id);
layer_t *find_layer_by_id(layer_t *head, int id);
void add_gate_id_to_layer(layer_t *layer, int id);
gate_t *init_gate(int type, int input1, int input2, int output);
void add_gate_to_circuit(circuit_t *circuit, gate_t *gate);
gate_t *find_gate_from_circuit_by_input(circuit_t *circuit, int input);
gate_t *find_gate_from_circuit_by_output(circuit_t *circuit, int output);
gate_t *find_gate_from_circuit_by_id(circuit_t *circuit, int id);
int traversal(gate_t *gate);

int main(int argc, char *argv[])
{
  int i, num_gate, num_wire, key_size, num_inputs;
  int type, input1, input2, output;
  int id;
  unsigned int *rows;
  gate_t *gate;
  circuit_t *circuit;
  layer_t *head, *prev, *curr;

  circuit = init_circuit();
  num_gate = aes_num_gate;
  num_wire = aes_num_wire;
  num_inputs = aes_key_size + 128;
  key_size = aes_key_size; 
  rows = (unsigned int *)aes_rows;

  for (i=0; i<num_gate; i++)
  {
    id = 4*i;
    type = rows[id];

    switch (type)
    {
      case GATE_TYPE_AND:
      case GATE_TYPE_XOR:
        input1 = rows[id+1];
        input2 = rows[id+2];
        output = rows[id+3];
        break;
      case GATE_TYPE_INV:
      default:
        input1 = rows[4*i+1];
        input2 = -1;
        output = rows[4*i+3];
    }
    gate = init_gate(id, type, input1, input2, output);
    add_gate_to_circuit(circuit, gate);
  }

  for (i=1; i<=num_layers; i++)
  {
    curr = init_layer(i);
    if (i == 1)
      head = layer;
    else
    {
      prev = find_layer_by_id(head, id);
      prev->next = curr;
    }
  }

  for (i=1; i<=num_layers; i++)
  {
    id = 
  }

  printf("# of gates in the circuit: %d\n", circuit->num);

  return 0;
}

circuit_t *init_circuit(void)
{
  circuit_t *ret;
  ret = (circuit_t *)calloc(1, sizeof(circuit_t));

  return ret;
}

layer_t *init_layer(int id)
{
  layer_t *ret;
  ret = (layer_t *)calloc(1, sizeof(layer_t));
  ret->id = id;
  ret->num = num;

  for (i=0; i<1000; i++)
  {
    ret->idlst[i] = -1;
  }

  return ret;
}

layer_t *find_layer_by_id(layer_t *head, int id)
{
  layer_t *ret, *curr;
  curr = head;
  ret = NULL;

  while (curr)
  {
    if (curr->id == id)
    {
      ret = curr;
      break;
    }
  }

  return ret;
}

void add_gate_id_to_layer(layer_t *layer, int id)
{
  int i;

  for (i=0; i<1000; i++)
  {
    if (layer->idlst[i] == id)
      break;

    if (layer->idlst[i] != -1)
    {
      layer->idlst[i] = id;
      break;
    }
  }
}

gate_t *init_gate(int id, int type, int input1, int input2, int output)
{
  gate_t *ret;
  ret = (gate_t *)calloc(1, sizeof(gate_t));

  ret->id = id;
  ret->type = type;
  ret->input1 = input1;
  ret->input2 = input2;
  ret->output = output;

  return ret;
}

void add_gate_to_circuit(circuit_t *circuit, gate_t *gate)
{
  gate_t *tmp;

  tmp = circuit->head;
  circuit->head = gate;
  gate->next = tmp;
  circuit->num++;
}

gate_t *find_gate_from_circuit_by_input(circuit_t *circuit, int input)
{
  gate_t *curr, *ret;

  curr = circuit->head;
  ret = NULL;

  while (curr)
  {
    if (curr->input1 == input || curr->input2 == input)
    {
      ret = curr;
      break;
    }
    curr = curr->next;
  }

  return ret;
}

gate_t *find_gate_from_circuit_by_output(circuit_t *circuit, int output)
{
  gate_t *curr, *ret;

  curr = circuit->head;
  ret = NULL;

  while (curr)
  {
    if (curr->output == output)
    {
      ret = curr;
      break;
    }
    curr = curr->next;
  }

  return ret;
}

gate_t *find_gate_from_circuit_by_id(circuit_t *circuit, int id)
{
  gate_t *curr, *ret;

  curr = circuit->head;
  ret = NULL;

  while (curr)
  {
    if (curr->id == id)
    {
      ret = curr;
      break;
    }
    curr = curr->next;
  }

  return ret;
}
