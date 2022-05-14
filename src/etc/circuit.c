#include <dpi/circuit.h>
#include <dpi/debug.h>
#include <dpi/defines.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "bit_op.h"

#define MAX_LINE_LENGTH 4096

int gate_operation(circuit_t *circuit, int idx);
wire_t *get_wire(circuit_t *circuit, int idx);
int get_wire_enabled(circuit_t *circuit, int idx);
void set_wire_disabled(circuit_t *circuit, int idx);

gateq_t *init_gateq(void);
void free_gateq(gateq_t *gateq);

/**
 * @brief initialize the circuit from the circuit file
 * @param cname the circuit file
 */
circuit_t *init_circuit(const char *cname)
{
  fstart("cname: %s", cname);
  assert(cname != NULL);

  int i, j, x, y, cnt, inum, onum, nnum, idx, tmp, found;
  circuit_t *ret;
  FILE *fp;
  char line[MAX_LINE_LENGTH] = {0, };
  char *init, *ptr;
  int nexts[MAX_NEXT_GATES] = {-1, };
  gate_t *gate;
  wire_t *wire;

  ret = (circuit_t *)calloc(1, sizeof(circuit_t));
  cnt = 0;
  ret->gateq = init_gateq();

  imsg(DPI_DEBUG_CIRCUIT, "initialize the circuit from %s", cname);
  fp = fopen(cname, "r");

  if (strstr(cname, "aes_128"))
  {
    ret->type = MPC_CIRCUIT_BRISTOL_AES_128;
    imsg(DPI_DEBUG_CIRCUIT, "AES-128 Circuit");
  }
  else if (strstr(cname, "aes_192"))
  {
    ret->type = MPC_CIRCUIT_BRISTOL_AES_192;
    imsg(DPI_DEBUG_CIRCUIT, "AES-192 Circuit");
  }
  else if (strstr(cname, "aes_256"))
  {
    ret->type = MPC_CIRCUIT_BRISTOL_AES_256;
    imsg(DPI_DEBUG_CIRCUIT, "AES-256 Circuit");
  }
  else if (strstr(cname, "test1"))
  {
    ret->type = MPC_CIRCUIT_TEST_1;
    imsg(DPI_DEBUG_CIRCUIT, "TEST-1 Circuit");
  }
  else if (strstr(cname, "test2"))
  {
    ret->type = MPC_CIRCUIT_TEST_2;
    imsg(DPI_DEBUG_CIRCUIT, "TEST-2 Circuit");
  }
  else if (strstr(cname, "test3"))
  {
    ret->type = MPC_CIRCUIT_TEST_3;
    imsg(DPI_DEBUG_CIRCUIT, "TEST-3 Circuit");
  }
  else
  {
    ret->type = MPC_CIRCUIT_BRISTOL_AES_128;
    imsg(DPI_DEBUG_CIRCUIT, "AES-128 Circuit");
  }

  // # of gates and # of wires
  fgets(line, MAX_LINE_LENGTH, fp);
  init = ptr = line;
  while (*ptr != ' ')
    ptr++;
  ret->gnum = char_to_int(init, ptr - init, 10);
  ret->gates = (gate_t **)calloc(ret->gnum, sizeof(gate_t *));
  imsg(DPI_DEBUG_CIRCUIT, "# of Gates: %d", ret->gnum);

  ptr++;
  init = ptr;
  while (*ptr != '\n')
    ptr++;
  ret->wnum = char_to_int(init, ptr - init, 10);
  ret->wires = (wire_t **)calloc(ret->wnum, sizeof(wire_t *));
  for (i=0; i<ret->wnum; i++)
    ret->wires[i] = init_wire(i);
  imsg(DPI_DEBUG_CIRCUIT, "# of Wires: %d", ret->wnum);

  // # of circuit inputs, # of wires per input, ...
  fgets(line, MAX_LINE_LENGTH, fp);
  init = ptr = line;
  while (*ptr != ' ')
    ptr++;
  ret->inum = char_to_int(init, ptr - init, 10);
  ret->ilens = (uint8_t *)calloc(ret->inum, sizeof(uint8_t));
  ret->inputs = (uint8_t **)calloc(ret->inum, sizeof(uint8_t *));
  idx = 0;
  imsg(DPI_DEBUG_CIRCUIT, "# of Circuit Inputs: %d", ret->inum);
  for (i=0; i<ret->inum; i++)
  {
    ptr++;
    init = ptr;
    while (*ptr != ' ' && *ptr != '\n')
      ptr++;
    ret->ilens[idx] = char_to_int(init, ptr - init, 10);
    ret->inputs[idx] = (uint8_t *)calloc(ret->ilens[idx], sizeof(uint8_t));
    imsg(DPI_DEBUG_CIRCUIT, "  %d> # of Wires: %d", idx, ret->ilens[idx]);
    idx++;
  }

  // # of circuit outputs, # of wires per output, ...
  fgets(line, MAX_LINE_LENGTH, fp);
  init = ptr = line;
  while (*ptr != ' ')
    ptr++;
  ret->onum = char_to_int(init, ptr - init, 10);
  ret->olens = (uint8_t *)calloc(ret->onum, sizeof(uint8_t));
  ret->obits = (uint8_t **)calloc(ret->onum, sizeof(uint8_t *));
  ret->obytes = (uint8_t **)calloc(ret->onum, sizeof(uint8_t *));
  idx = 0;
  imsg(DPI_DEBUG_CIRCUIT, "# of Circuit Outputs: %d", ret->onum);
  for (i=0; i<ret->onum; i++)
  {
    ptr++;
    init = ptr;
    while (*ptr != ' ' && *ptr != '\n')
      ptr++;
    ret->olens[idx] = char_to_int(init, ptr - init, 10);
    ret->obits[idx] = (uint8_t *)calloc(ret->olens[idx], sizeof(uint8_t));
    ret->obytes[idx] = (uint8_t *)calloc(ret->olens[idx]/8, sizeof(uint8_t));
    imsg(DPI_DEBUG_CIRCUIT, "  %d> # of Wires: %d", idx, ret->olens[idx]);
    idx++;
  }

  // void
  fgets(line, MAX_LINE_LENGTH, fp);

  // gates
  for (idx=0; idx<ret->gnum; idx++)
  {
    fgets(line, MAX_LINE_LENGTH, fp);
    if (feof(fp))
      break;

    init = ptr = line;
    while (*ptr != ' ')
      ptr++;
    inum = char_to_int(init, ptr - init, 10);

    ptr++;
    init = ptr;
    while (*ptr != ' ')
      ptr++;
    onum = char_to_int(init, ptr - init, 10);
    ret->gates[idx] = init_gate(idx, inum, onum);

    dmsg(DPI_DEBUG_CIRCUIT, "%d> line: %s", idx, line);
    dmsg(DPI_DEBUG_CIRCUIT, "%d> # of gate inputs: %d, # of gate outputs: %d", idx, inum, onum);

    for (i=0; i<inum; i++)
    {
      ptr++;
      init = ptr;
      while (*ptr != ' ')
        ptr++;
      tmp = char_to_int(init, ptr - init, 10);
      add_wire(ret->gates[idx], tmp, MPC_GATE_INPUT_WIRE);
    }

    for (i=0; i<onum; i++)
    {
      ptr++;
      init = ptr;
      while (*ptr != ' ')
        ptr++;
      tmp = char_to_int(init, ptr - init, 10);
      add_wire(ret->gates[idx], tmp, MPC_GATE_OUTPUT_WIRE);
    }

    ptr++;
    init = ptr;
    while (*ptr != '\n')
      ptr++;

    tmp = ptr - init;
    if (tmp == 3 && !strncmp(init, "XOR", tmp))
    {
      add_type(ret->gates[idx], MPC_GATE_TYPE_XOR);
    }
    else if (tmp == 3 && !strncmp(init, "AND", tmp))
    {
      add_type(ret->gates[idx], MPC_GATE_TYPE_AND);
    }
    else if (tmp == 3 && !strncmp(init, "INV", tmp))
    {
      add_type(ret->gates[idx], MPC_GATE_TYPE_INV);
    }
    else if (tmp == 2 && !strncmp(init, "EQ", tmp))
    {
      add_type(ret->gates[idx], MPC_GATE_TYPE_EQ);
    }
    else if (tmp == 3 && !strncmp(init, "EQW", tmp))
    {
      add_type(ret->gates[idx], MPC_GATE_TYPE_EQW);
    }
    else if (tmp == 4 && !strncmp(init, "MAND", tmp))
    {
      add_type(ret->gates[idx], MPC_GATE_TYPE_MAND);
    }
    else
    {
      emsg("parsing error");
      exit(1);
    }
    dmsg(DPI_DEBUG_CIRCUIT, "gate: type: %d, inum: %d, onum: %d", ret->gates[idx]->type, inum, onum);
  }

  fclose(fp);
  imsg(DPI_DEBUG_CIRCUIT, "Initialize the gates success");
  imsg(DPI_DEBUG_CIRCUIT, "Now we find next gates");

  for (i=0; i<ret->gnum; i++)
  {
    gate = ret->gates[i];
    for (j=0; j<gate->inum; j++)
    {
      wire = ret->wires[gate->inputs[j]];
      wire->nexts[wire->nnum++] = i;
    }
  }


#ifdef CIRCUIT_DEBUG
  for (i=0; i<ret->gnum; i++)
  {
    printf("Gate (%d):\n", ret->gates[i]->id);
    printf("  - Input Wire (%d): ", ret->gates[i]->inum);
    for (j=0; j<ret->gates[i]->inum; j++)
      printf("%d ", ret->gates[i]->inputs[j]);
    printf("\n");
    printf("  - Output Wire (%d): ", ret->gates[i]->onum);
    for (j=0; j<ret->gates[i]->onum; j++)
      printf("%d ", ret->gates[i]->outputs[j]);
    printf("\n");
    
    switch (ret->gates[i]->type)
    {
      case MPC_GATE_TYPE_XOR:
        printf("  - Type: XOR\n");
        break;
      case MPC_GATE_TYPE_AND:
        printf("  - Type: AND\n");
        break;
      case MPC_GATE_TYPE_INV:
        printf("  - Type: INV\n");
        break;
      case MPC_GATE_TYPE_MAND:
        printf("  - Type: MAND\n");
        break;
      default:
        break;
    }
  }

  for (i=0; i<ret->wnum; i++)
  {
    printf("Wire (%d): ", ret->wires[i]->id);
    for (j=0; j<ret->wires[i]->nnum; j++)
      printf("%d ", ret->wires[i]->nexts[j]);
    printf("\n");
  }
#endif /* CIRCUIT_DEBUG */

  imsg(DPI_DEBUG_CIRCUIT, "Complete in initializing the circuit");

  ffinish("ret: %p", ret);
  return ret;
}

int get_circuit_type(circuit_t *circuit)
{
  fstart("circuit: %p", circuit);
  assert(circuit != NULL);

  int ret;
  ret = circuit->type;

  ffinish("ret: %d", ret);
  return ret;
}

void set_circuit_role(circuit_t *circuit, int role)
{
  fstart("circuit: %p, role: %d", circuit, role);
  assert(circuit != NULL);

  circuit->role = role;

  ffinish();
}

uint8_t reverse_bytes(uint8_t i)
{
  return ((8 * (15 - (i / 8))) + (i % 8));
}

/**
 * @brief Add the circuit input to the circuit (the input is added in bits)
 * @param circuit the circuit
 * @param input the input (in bytes)
 * @param input ilen the length of the input (in bytes)
 */
void add_input(circuit_t *circuit, uint8_t *input, int ilen)
{
  fstart("circuit: %p, input: %p, ilen: %d", circuit, input, ilen);
  assert(circuit != NULL);
  assert(input != NULL);
  assert(ilen > 0);

  int i;
  uint8_t *bits;
  uint8_t tmp[BUF_SIZE] = {0, };

#ifdef CIRCUIT_DEBUG
  printf("Input (in bytes):\n");
  for (i=0; i<ilen; i++)
    printf("%02x ", input[i]);
  printf("\n");
#endif /* CIRCUIT_DEBUG */

  byte_to_bit(input, 8, ilen, tmp);
  
  bits = (uint8_t *)calloc(ilen * 8, sizeof(uint8_t));

  for (i=0; i<ilen*8; i++)
  {
    if (circuit->type == MPC_CIRCUIT_BRISTOL_AES_128)
      bits[ilen*8-1-i] = tmp[i];
    else
      bits[i] = tmp[i];
  }

#ifdef CIRCUIT_DEBUG
  printf("Input (in bits):\n");
  for (i=0; i<ilen*8; i++)
    printf("%02x ", bits[i]);
  printf("\n");
#endif /* CIRCUIT_DEBUG */

  circuit->inputs[circuit->iset++] = bits;
  assert(circuit->iset <= circuit->inum);

  ffinish();
}

void change_input(circuit_t *circuit, int idx, uint8_t *input, int ilen)
{
  fstart("circuit: %p, idx: %d, input: %p, ilen: %d", circuit, idx, input, ilen);
  assert(circuit != NULL);
  assert(input != NULL);
  assert(ilen > 0);

  int i;
  uint8_t *bits;
  uint8_t tmp[BUF_SIZE] = {0, };

#ifdef CIRCUIT_DEBUG
  printf("Input (in bytes):\n");
  for (i=0; i<ilen; i++)
    printf("%02x ", input[i]);
  printf("\n");
#endif /* CIRCUIT_DEBUG */

  byte_to_bit(input, 8, ilen, tmp);
  
  bits = (uint8_t *)calloc(ilen * 8, sizeof(uint8_t));

  for (i=0; i<ilen*8; i++)
  {
    if (circuit->type == MPC_CIRCUIT_BRISTOL_AES_128)
      bits[ilen*8-1-i] = tmp[i];
    else
      bits[i] = tmp[i];
  }

#ifdef CIRCUIT_DEBUG
  printf("Input (in bits):\n");
  for (i=0; i<ilen*8; i++)
    printf("%02x ", bits[i]);
  printf("\n");
#endif /* CIRCUIT_DEBUG */

  if (circuit->inputs[idx])
    free(circuit->inputs[idx]);
  if (circuit->iset < circuit->inum)
    circuit->iset++;
  circuit->inputs[idx] = bits;

  ffinish();
}

/**
 * @brief Prepare the circuit to be processed. Add ready gates to the gate queue and check inputs
 * @param circuit the circuit
 */
void prepare_circuit_operation(circuit_t *circuit)
{
  fstart("circuit: %p", circuit);
  assert(circuit != NULL);

  int i, j, idx, inum, cnt;
  gate_t *gate;

  inum = circuit->inum;
  idx = 0;
  cnt = 0;

  // check if the inputs are all set
  imsg(DPI_DEBUG_CIRCUIT, "inum: %d, circuit->iset: %d", inum, circuit->iset);
  assert(inum == circuit->iset);

  // move input bits to the circuit
  for (i=0; i<inum; i++)
  {
    for (j=0; j<circuit->ilens[i]; j++)
      set_wire_value(circuit, idx+j, circuit->inputs[i][j]);
    idx += circuit->ilens[i];
  }

#ifdef CIRCUIT_DEBUG
  idx = 0;
  for (i=0; i<inum; i++)
  {
    for (j=0; j<circuit->ilens[i]; j++)
    {
      printf("Wire (%d): Value: %d\n", idx+j, get_wire_value(circuit, idx+j));
    }
    idx += circuit->ilens[i];
  }

  uint8_t tmp[16];
  printf("Key in Circuit: ");
  for (i=0; i<8; i++)
    tmp[i] = circuit->wires[i]->value;
  for (i=0; i<8; i+=8)
    printf("%02x ", bit_to_byte(tmp, 8, i));
  printf("\n");

  printf("Input in Circuit: ");
  for (i=8; i<16; i++)
    tmp[i] = circuit->wires[i]->value;
  for (i=8; i<16; i+=8)
    printf("%02x ", bit_to_byte(tmp, 8, i));
  printf("\n");
#endif /* CIRCUIT_DEBUG */

  // add the gates that are ready to be evaluated to the gate queue
  for (i=0; i<circuit->gnum; i++)
  {
    gate = circuit->gates[i];
    if (check_gate_is_ready(circuit, gate))
    {
      enqueue(circuit, gate);
      cnt++;
    }
  }
  imsg(DPI_DEBUG_CIRCUIT, "# of gates added: %d", cnt);

  ffinish();
}

void proceed_one_depth(circuit_t *circuit)
{
  fstart("circuit: %p", circuit);
  assert(circuit != NULL);

  int i, j, ret;
  gate_t *gate, *ngate;
  wire_t *wire;

  gate = dequeue(circuit, TRUE, TRUE);
  while (gate)
  {
    //printf("gate->id: %d\n", gate->id);
    ret = gate_operation(circuit, gate->id);
    if (!ret)
    {
      emsg("error should not happen in the gate operation function");
      exit(1);
    }

    dmsg(DPI_DEBUG_CIRCUIT, "Gate %d>\n", gate->id);
    for (i=0; i<gate->onum; i++)
    {
      wire = circuit->wires[gate->outputs[i]];

      for (j=0; j<wire->nnum; j++)
      {
        ngate = circuit->gates[wire->nexts[j]];

        if (check_gate_is_ready(circuit, ngate))
        {
          enqueue(circuit, ngate);
          dmsg(DPI_DEBUG_CIRCUIT, "  Gate %d's next Gate %d through Wire %d is enqueued\n", gate->id, ngate->id, wire->id);
        }
        else
        {
          dmsg(DPI_DEBUG_CIRCUIT, "  Gate %d's next Gate %d through Wire %d is not enqueued\n", gate->id, ngate->id, wire->id);
        }
      }
    }
  
    dmsg(DPI_DEBUG_CIRCUIT, "circuit->gateq->num: %d\n", circuit->gateq->num);
    gate = dequeue(circuit, TRUE, TRUE);
  }
  
#ifdef CIRCUIT_DEBUG
  printf("After one depth: gateq->num: %d\n", circuit->gateq->num);
  gate = dequeue(circuit, FALSE, FALSE);
  if (gate)
  {
    printf("In Queue: Gate %d (Type: %d)\n", gate->id, gate->type);
    enqueue(circuit, gate);
  }
#endif /* CIRCUIT_DEBUG */

  ffinish();
}

void proceed_and_gates(circuit_t *circuit)
{
  fstart("circuit: %p", circuit);
  assert(circuit != NULL);

  int i, j, k, num, ret;
  gate_t *gate, *ngate;
  wire_t *wire;
  gateq_t *gateq;

  gateq = circuit->gateq;
  num = gateq->num;

  for (i=0; i<num; i++)
  {
    gate = dequeue(circuit, FALSE, FALSE);
    ret = gate_operation(circuit, gate->id);
    if (!ret)
    {
      emsg("Should not be happened");
      exit(1);
    }

    for (j=0; j<gate->onum; j++)
    {
      wire = circuit->wires[gate->outputs[j]];

      for (k=0; k<wire->nnum; k++)
      {
        ngate = circuit->gates[wire->nexts[k]];

        if (check_gate_is_ready(circuit, ngate))
          enqueue(circuit, ngate);
      }
    }
  }

  ffinish();
}

void proceed_full_depths(circuit_t *circuit)
{
  fstart("circuit: %p", circuit);
  assert(circuit != NULL);

  int i, j, iter, num, tmp, sidx, eidx, iidx;
  uint8_t *input, *tout;
  uint8_t byte;
  gateq_entry_t *curr;
  
  iter = 0;
  num = 0;
  
#ifdef CIRCUIT_DEBUG
  printf("%d iteration (# of gates: %d):\n", iter++, circuit->gateq->num);
  curr = NULL;
  for (i=0; i<circuit->gateq->num; i++)
  {
    if (!curr)
      curr = circuit->gateq->start;
    else
      curr = curr->next;
    printf("%d ", curr->gate->id);
    num++;
    if (num % 32 == 0)
      printf("\n");
  }
  if (num % 32 != 0)
    printf("\n");
  printf("\n");
  num = 0;
#endif /* CIRCUIT_DEBUG */

  while (circuit->gateq->num > 0)
  {
    dmsg(DPI_DEBUG_CIRCUIT, "before proceed_one_depth: %d\n", circuit->gateq->num);
    proceed_one_depth(circuit);
    dmsg(DPI_DEBUG_CIRCUIT, "after proceed_one_depth: %d\n", circuit->gateq->num);

#ifdef CIRCUIT_DEBUG
    printf("%d iteration (# of AND gates: %d):\n", iter++, circuit->gateq->num);
    curr = NULL;

    for (i=0; i<circuit->gateq->num; i++)
    {
      if (!curr)
        curr = circuit->gateq->start;
      else
        curr = curr->next;
      printf("%d ", curr->gate->id);
      num++;
      if (num % 32 == 0)
        printf("\n");
    }
    if (num % 32 != 0)
      printf("\n");
    printf("\n");
    num = 0;
#endif /* CIRCUIT_DEBUG */

    dmsg(DPI_DEBUG_CIRCUIT, "before proceed_and_gates: %d\n", circuit->gateq->num);
    proceed_and_gates(circuit);
    dmsg(DPI_DEBUG_CIRCUIT, "after proceed_and_gates: %d\n", circuit->gateq->num);
  }

#ifdef CIRCUIT_DEBUG
  for (i=0; i<circuit->wnum; i++)
    printf("Wire (%d): Value: %d\n", circuit->wires[i]->id, get_wire_value(circuit, i));
#endif /* CIRCUIT_DEBUG */

  tmp = 0;
  for (i=0; i<circuit->onum; i++)
    tmp += circuit->olens[i];

  sidx = circuit->wnum - tmp;
  for (i=0; i<circuit->onum; i++)
  {
    eidx = sidx + circuit->olens[i];
    tout = (uint8_t *)calloc(circuit->olens[i], sizeof(uint8_t));
    for (j=0; sidx+j<eidx; j++)
      tout[j] = get_wire_value(circuit, sidx+j);
    for (j=0; j<circuit->olens[i]; j++)
    {
      if (circuit->type == MPC_CIRCUIT_BRISTOL_AES_128)
        circuit->obits[i][circuit->olens[i] - 1 - j] = tout[j];
      else
        circuit->obits[i][j] = tout[j];
    }
    free(tout);
    sidx = eidx;
  }

  for (i=0; i<circuit->onum; i++)
  {
    tmp = circuit->olens[i] / 8;
    for (j=0; j<tmp; j++)
      circuit->obytes[i][j] = bit_to_byte(circuit->obits[i], 8, 8*j);
  }

  ffinish();
}

void proceed(circuit_t *circuit)
{
  fstart("circuit: %p", circuit);
  assert(circuit != NULL);

  int i, j, ret, tmp, sidx, eidx;
  uint8_t buf[1024] = {0, };
  uint8_t *tout;

  for (i=0; i<circuit->gnum; i++)
    ret = gate_operation(circuit, i);

  tmp = 0;
  for (i=0; i<circuit->onum; i++)
    tmp += circuit->olens[i];

  sidx = circuit->wnum - tmp;
  for (i=0; i<circuit->onum; i++)
  {
    eidx = sidx + circuit->olens[i];
    tout = (uint8_t *)calloc(circuit->olens[i], sizeof(uint8_t));
    for (j=0; sidx+j<eidx; j++)
      tout[j] = get_wire_value(circuit, sidx+j);
    for (j=0; j<circuit->olens[i]; j++)
    {
      if (circuit->type == MPC_CIRCUIT_BRISTOL_AES_128)
        circuit->obits[i][circuit->olens[i]-1-j] = tout[j];
      else
        circuit->obits[i][j] = tout[j];
    }
    sidx = eidx;
  }

  for (i=0; i<circuit->onum; i++)
  {
    for (j=0; j<circuit->olens[i]; j++)
      buf[j] = circuit->obits[i][j];
    tmp = circuit->olens[i] / 8;
    for (j=0; j<tmp; j++)
      circuit->obytes[i][j] = bit_to_byte(buf, 8, 8*j);
  }


  ffinish();
}

int get_num_of_outputs(circuit_t *circuit)
{
  fstart("circuit: %p", circuit);
  assert(circuit != NULL);

  int ret;
  ret = circuit->onum;

  ffinish("ret: %d", ret);
  return ret;
}

uint8_t *get_output_bits(circuit_t *circuit, int idx, int *olen)
{
  fstart("circuit: %p, olen: %p", circuit, olen);
  assert(circuit != NULL);
  assert(olen != NULL);
  assert(idx >= 0 && idx <= circuit->onum);

  uint8_t *ret;
  ret = circuit->obits[idx];
  *olen = circuit->olens[idx];

  ffinish("ret: %p", ret);
  return ret;
}

uint8_t *get_output_bytes(circuit_t *circuit, int idx, int *olen)
{
  fstart("circuit: %p, olen: %p", circuit, olen);
  assert(circuit != NULL);
  assert(olen != NULL);
  assert(idx >= 0 && idx <= circuit->onum);

  uint8_t *ret;
  ret = circuit->obytes[idx];
  *olen = circuit->olens[idx] / 8;

  ffinish("ret: %p", ret);
  return ret;
}

void free_circuit(circuit_t *circuit)
{
  fstart("circuit: %p", circuit);

  int i;

  if (circuit)
  {
    if (circuit->gateq)
      free_gateq(circuit->gateq);

    for (i=0; i<circuit->gnum; i++)
      free_gate(circuit->gates[i]);
    free(circuit->gates);

    for (i=0; i<circuit->wnum; i++)
      free_wire(circuit->wires[i]);
    free(circuit->wires);

    for (i=0; i<circuit->inum; i++)
      free(circuit->inputs[i]);
    free(circuit->ilens);
    free(circuit->inputs);

    for (i=0; i<circuit->onum; i++)
    {
      free(circuit->obits[i]);
      free(circuit->obytes[i]);
    }
    free(circuit->olens);
    free(circuit->obits);
    free(circuit->obytes);
  }

  ffinish();
}

gate_t *init_gate(int id, uint16_t inum, uint16_t onum)
{
  fstart("inum: %d, onum: %d", inum, onum);
  assert(inum > 0);
  assert(onum > 0);

  gate_t *ret;
  ret = (gate_t *)calloc(1, sizeof(gate_t));
  ret->type = -1;
  ret->id = id;
  ret->inum = inum;
  ret->inputs = (uint16_t *)calloc(inum, sizeof(uint16_t));
  ret->ivalues = (uint8_t *)calloc(inum, sizeof(uint8_t));
  ret->enabled = (uint8_t *)calloc(inum, sizeof(uint8_t));
  ret->onum = onum;
  ret->outputs = (uint16_t *)calloc(onum, sizeof(uint16_t));

  ffinish("ret: %p", ret);
  return ret;
}

void add_type(gate_t *gate, uint8_t type)
{
  fstart("type: %u", type);

  gate->type = type;

  ffinish();
}

void add_wire(gate_t *gate, uint16_t widx, uint8_t is_output)
{
  fstart("gate: %p, widx: %u, is_output: %u", gate, widx, is_output);

  if (is_output)
  {
    gate->outputs[gate->oset] = widx;
    gate->oset++;
    assert(gate->oset <= gate->onum);
  }
  else
  {
    gate->inputs[gate->iset] = widx;
    gate->iset++;
    assert(gate->iset <= gate->inum);
  }

  ffinish();
}

/*
void add_next_gates(wire_t *wire, int nnum, int *nexts)
{
  fstart("wire: %p, nnum: %d, nexts: %p", wire, nnum, nexts);
  assert(wire != NULL);
  assert(nnum >= 0);
  assert(nexts != NULL);

  int i;
  wire->nnum = nnum;
  wire->nexts = (uint16_t *)calloc(nnum, sizeof(uint16_t));

  for (i=0; i<nnum; i++)
    wire->nexts[i] = nexts[i];

  ffinish();
}
*/

int check_gate_is_ready(circuit_t *circuit, gate_t *gate)
{
  fstart("circuit: %p, gate: %p", circuit, gate);
  assert(circuit != NULL);
  assert(gate != NULL);

  int i, ret;
  ret = TRUE;

  for (i=0; i<gate->inum; i++)
  {
    if (!gate->enabled[i])
    {
      ret = FALSE;
      break;
    }
  }

  ffinish("ret: %d", ret);
  return ret;
}

int gate_operation(circuit_t *circuit, int idx)
{
  fstart("circuit: %p, idx: %d", circuit, idx);
  assert(circuit != NULL);

  int ret, i, i1, i2, o1, type;
  gate_t *gate;

  ret = FALSE;
  gate = circuit->gates[idx];

  //if (!check_gate_is_ready(circuit, gate)) goto out;
  
  type = gate->type;
  switch (type)
  {
    case MPC_GATE_TYPE_XOR:
      set_wire_value(circuit, gate->outputs[0], xor(gate->ivalues[0], gate->ivalues[1]));
      dmsg(DPI_DEBUG_CIRCUIT, "ID: %d (XOR)> i1: %d (Wire %d), i2: %d (Wire %d), o: %d (Wire %d)\n", gate->id, gate->ivalues[0], gate->inputs[0], gate->ivalues[1], gate->inputs[1], get_wire_value(circuit, gate->outputs[0]), gate->outputs[0]);
      break;

    case MPC_GATE_TYPE_AND:
      set_wire_value(circuit, gate->outputs[0], and(gate->ivalues[0], gate->ivalues[1]));
      dmsg(DPI_DEBUG_CIRCUIT, "ID: %d (AND)> i1: %d (Wire %d), i2: %d (Wire %d), o: %d (Wire %d)\n", gate->id, gate->ivalues[0], gate->inputs[0], gate->ivalues[1], gate->inputs[1], get_wire_value(circuit, gate->outputs[0]), gate->outputs[0]);
      break;

    case MPC_GATE_TYPE_INV:
      if (circuit->role == MPC_CIRCUIT_RANDOMIZATION_NONE)
        set_wire_value(circuit, gate->outputs[0], inv(gate->ivalues[0]));
      else if (circuit->role == MPC_CIRCUIT_RANDOMIZATION_FLIP)
        set_wire_value(circuit, gate->outputs[0], gate->ivalues[0]);
      dmsg(DPI_DEBUG_CIRCUIT, "ID: %d (INV)> i1: %d, o: %d\n", gate->id, gate->ivalues[0], get_wire_value(circuit, gate->outputs[0]));
      break;

    case MPC_GATE_TYPE_EQ:
      set_wire_value(circuit, gate->outputs[0], gate->ivalues[0]);
      break;

    case MPC_GATE_TYPE_EQW:
      set_wire_value(circuit, gate->outputs[0], get_wire_value(circuit, gate->inputs[0]));
      break;

    case MPC_GATE_TYPE_MAND:
      i1 = 0;
      i2 = gate->inum / 2;
      o1 = 0;

      for (i=0; i<(gate->inum / 2); i++)
      {
        set_wire_value(circuit, gate->outputs[o1+i], 
            and(gate->ivalues[i1+i], gate->ivalues[i2+i]));
      }
      break;

    default:
      emsg("invalid operation: should not be happened");
      exit(1);
  }

  ret = TRUE;
out:
  ffinish("ret: %d", ret);
  return ret;
}

void free_gate(gate_t *gate)
{
  fstart("gate: %p", gate);
  
  if (gate)
  {
    if (gate->inputs)
      free(gate->inputs);

    if (gate->outputs)
      free(gate->outputs);
  }

  ffinish();
}

wire_t *init_wire(int id)
{
  fstart("id: %d", id);

  wire_t *ret;
  ret = (wire_t *)calloc(1, sizeof(wire_t));
  ret->id = id;

  ffinish("ret: %p", ret);
  return ret;
}

void free_wire(wire_t *wire)
{
  fstart("wire: %p", wire);

  if (wire)
  {
    free(wire);
  }

  ffinish();
}

wire_t *get_wire(circuit_t *circuit, int idx)
{
  fstart("circuit: %p, idx: %d", circuit, idx);
  assert(circuit != NULL);
  
  wire_t *ret;
  ret = circuit->wires[idx];

  ffinish("ret: %p", ret);
  return ret;
}

int get_wire_value(circuit_t *circuit, int idx)
{
  fstart("circuit: %p, idx: %d", circuit, idx);
  assert(circuit != NULL);

  int ret;
  ret = circuit->wires[idx]->value;

  ffinish("ret: %d", ret);
  return ret;
}

int get_wire_enabled(circuit_t *circuit, int idx)
{
  fstart("circuit: %p, idx: %d", circuit, idx);
  assert(circuit != NULL);

  int ret;
  ret = circuit->wires[idx]->enabled;

  ffinish("ret: %d", ret);
  return ret;
}

void set_wire_value(circuit_t *circuit, int idx, int value)
{
  fstart("circuit: %p, idx: %d, value: %d", circuit, idx, value);
  assert(circuit != NULL);
  assert(idx >= 0);
  assert(value == 0 || value == 1);

  int i, j;
  wire_t *wire;
  gate_t *gate;
  wire = circuit->wires[idx];

  wire->enabled = 1;
  wire->value = value;

  for (i=0; i<wire->nnum; i++)
  {
    gate = circuit->gates[wire->nexts[i]];
    for (j=0; j<gate->inum; j++)
    {
      if (wire->id == gate->inputs[j])
      {
        gate->ivalues[j] = value;
        gate->enabled[j] = 1;
      }
    }
  }

  ffinish();
}

void set_wire_enabled(circuit_t *circuit, int idx)
{
  fstart("circuit: %p, idx: %d", circuit, idx);
  assert(circuit != NULL);
  assert(idx >= 0);

  ffinish();
}

void set_wire_disabled(circuit_t *circuit, int idx)
{
  fstart("circuit: %p, idx: %d", circuit, idx);
  assert(circuit != NULL);
  assert(idx >= 0);

  wire_t *wire;
  wire = circuit->wires[idx];

  wire->enabled = 0;

  ffinish();
}

/**
 * @brief allocate the memory for the gate queue
 */
gateq_t *init_gateq(void)
{
  fstart();

  gateq_t *ret;
  ret = (gateq_t *)calloc(1, sizeof(gateq_t));

  ffinish("ret: %p", ret);
  return ret;
}

/**
 * @brief add the gate to be processed to the gate queue
 * @param gateq the gate queue
 * @param gate the gate to be added
 */
void enqueue(circuit_t *circuit, gate_t *gate)
{
  fstart("circuit: %p, gate: %p", circuit, gate);
  assert(circuit != NULL);
  assert(gate != NULL);

  int i;
  gateq_t *gateq;
  gateq_entry_t *entry, *tmp;

  gateq = circuit->gateq;
  tmp = NULL;
  for (i=0; i<gateq->num; i++)
  {
    if (!tmp)
      tmp = gateq->start;
    else
      tmp = tmp->next;
    if (tmp->gate->id == gate->id)
      goto out;
  }

  entry = (gateq_entry_t *)calloc(1, sizeof(gateq_entry_t));
  entry->gate = gate;

  if (tmp)
  {
    tmp->next = entry;
    entry->prev = tmp;
  }
  else
  {
    gateq->start = entry;
  }
  gateq->end = entry;
  gateq->num++;

out:
  ffinish();
}

/**
 * @brief fetch the gate entry to be processed from the gate queue
 * @param gateq the gate queue
 * @param only_not_and only fetch the gate of which the type is not AND
 */
gate_t *dequeue(circuit_t *circuit, int only_not_and, int check)
{
  fstart("circuit: %p, only_not_and: %d, check: %d", circuit, only_not_and, check);
  assert(circuit != NULL);

  int i, num;
  gate_t *ret;
  gateq_t *gateq;
  gateq_entry_t *curr;
  ret = NULL;

  gateq = circuit->gateq;
  num = gateq->num;
  curr = gateq->start;
  if (!curr) goto out;

  curr = NULL;
  for (i=0; i<num; i++)
  {
    if (!curr)
      curr = gateq->start;
    else
      curr = curr->next;

    if (only_not_and 
        && (curr->gate->type == MPC_GATE_TYPE_AND || curr->gate->type == MPC_GATE_TYPE_MAND))
      continue;

    if (check && !check_gate_is_ready(circuit, curr->gate))
      continue;

    ret = curr->gate;
    if (curr->prev)
      curr->prev->next = curr->next;
    else
      gateq->start = curr->next;

    if (curr->next)
      curr->next->prev = curr->prev;
        
    gateq->num--;
    break;
  }
  assert(gateq->num >= 0);

out:
  ffinish("ret: %p", ret);
  return ret;
}

/**
 * @brief Deallocate the memory used for the gate queue
 * @param gateq the gate queue
 */
void free_gateq(gateq_t *gateq)
{
  fstart("gateq: %p", gateq);

  int i;
  gateq_entry_t *curr, *next;
  curr = next = NULL;

  if (gateq)
  {
    curr = gateq->start;
    for (i=0; i<gateq->num; i++)
    {
      if (curr)
      {
        next = curr->next;
        free(curr);
        curr = next;
      }
    }
    free(gateq);
  }

  ffinish();
}
