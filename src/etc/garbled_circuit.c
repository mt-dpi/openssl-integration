#include <dpi/garbled_circuit.h>
#include <dpi/debug.h>
#include <dpi/defines.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include "bit_op.h"

#define MAX_LINE_LENGTH 4096

int generate_garbled_table(garbled_circuit_t *gc, int idx);

int gc_gate_operation(garbled_circuit_t *gc, int idx);
gc_wire_t *get_gc_wire(garbled_circuit_t *gc, int idx);
int get_gc_wire_value(garbled_circuit_t *gc, int idx);
int get_gc_wire_enabled(garbled_circuit_t *gc, int idx);
void set_gc_wire_value(garbled_circuit_t *gc, int idx, uint8_t *msg, int mlen);
void set_gc_wire_disabled(garbled_circuit_t *gc, int idx);

gc_gateq_t *init_gc_gateq(void);

/**
 * @brief initialize the circuit from the circuit file
 * @param cname the circuit file
 */
garbled_circuit_t *init_garbled_circuit(const char *cname, int role)
{
  fstart("cname: %s", cname);
  assert(cname != NULL);
  assert(role == GARBLED_CIRCUIT_GARBLER || role == GARBLED_CIRCUIT_EVALUATOR);

  int i, j, rc, x, cnt, inum, onum, nnum, idx, tmp;
  garbled_circuit_t *ret;
  FILE *fp;
  char line[MAX_LINE_LENGTH] = {0, };
  char *init, *ptr;
  int nexts[MAX_NEXT_GATES] = {-1, };
  gc_gate_t *gate;
  gc_wire_t *wire;

  srand(time(NULL));
  ret = (garbled_circuit_t *)calloc(1, sizeof(garbled_circuit_t));
  cnt = 0;

  imsg(DPI_DEBUG_CIRCUIT, "initialize the garbled_circuit from %s", cname);
  fp = fopen(cname, "r");

  if (strstr(cname, "aes_128"))
  {
    ret->type = GARBLED_CIRCUIT_BRISTOL_AES_128;
    imsg(DPI_DEBUG_CIRCUIT, "AES-128 Circuit");
  }
  else if (strstr(cname, "aes_192"))
  {
    ret->type = GARBLED_CIRCUIT_BRISTOL_AES_192;
    imsg(DPI_DEBUG_CIRCUIT, "AES-192 Circuit");
  }
  else if (strstr(cname, "aes_256"))
  {
    ret->type = GARBLED_CIRCUIT_BRISTOL_AES_256;
    imsg(DPI_DEBUG_CIRCUIT, "AES-256 Circuit");
  }
  else if (strstr(cname, "test1"))
  {
    ret->type = GARBLED_CIRCUIT_TEST_1;
    imsg(DPI_DEBUG_CIRCUIT, "Test 1 Circuit");
  }
  else if (strstr(cname, "test2"))
  {
    ret->type = GARBLED_CIRCUIT_TEST_2;
    imsg(DPI_DEBUG_CIRCUIT, "Test 2 Circuit");
  }
  else
  {
    ret->type = GARBLED_CIRCUIT_BRISTOL_AES_128;
    imsg(DPI_DEBUG_CIRCUIT, "AES-128 Circuit");
  }

  ret->role = role;

  // # of gates and # of wires
  fgets(line, MAX_LINE_LENGTH, fp);
  init = ptr = line;
  while (*ptr != ' ')
    ptr++;
  ret->gnum = char_to_int((uint8_t *)init, ptr - init, 10);
  ret->gates = (gc_gate_t **)calloc(ret->gnum, sizeof(gc_gate_t *));
  imsg(DPI_DEBUG_CIRCUIT, "# of Garbled Gates: %d", ret->gnum);

  ptr++;
  init = ptr;
  while (*ptr != '\n')
    ptr++;
  ret->wnum = char_to_int((uint8_t *)init, ptr - init, 10);
  ret->wires = (gc_wire_t **)calloc(ret->wnum, sizeof(gc_wire_t *));
  for (i=0; i<ret->wnum; i++)
    ret->wires[i] = init_gc_wire(i, ret->role);
  imsg(DPI_DEBUG_CIRCUIT, "# of Garbled Circuit's Wires: %d", ret->wnum);

  // # of circuit inputs, # of wires per input, ...
  fgets(line, MAX_LINE_LENGTH, fp);
  init = ptr = line;
  while (*ptr != ' ')
    ptr++;
  ret->inum = char_to_int((uint8_t *)init, ptr - init, 10);
  ret->ilens = (uint16_t **)calloc(ret->inum, sizeof(uint16_t *));
  ret->inputs = (uint8_t ***)calloc(ret->inum, sizeof(uint8_t **));
  idx = 0;
  imsg(DPI_DEBUG_CIRCUIT, "# of Garbled Circuit Inputs: %d", ret->inum);
  for (i=0; i<ret->inum; i++)
  {
    ptr++;
    init = ptr;
    while (*ptr != ' ' && *ptr != '\n')
      ptr++;
    ret->ilens[idx] = (uint16_t *)calloc(char_to_int((uint8_t *)init, ptr - init, 10), 
        sizeof(uint16_t));
    ret->inputs[idx] = (uint8_t **)calloc(ret->ilens[idx], sizeof(uint8_t *));
    imsg(DPI_DEBUG_CIRCUIT, "  %d> # of Wires: %d", idx, ret->ilens[idx]);
    idx++;
  }

  // # of circuit outputs, # of wires per output, ...
  fgets(line, MAX_LINE_LENGTH, fp);
  init = ptr = line;
  while (*ptr != ' ')
    ptr++;
  ret->onum = char_to_int((uint8_t *)init, ptr - init, 10);
  ret->olens = (uint16_t *)calloc(ret->onum, sizeof(uint16_t));
  ret->obits = (uint8_t **)calloc(ret->onum, sizeof(uint8_t *));
  ret->obytes = (uint8_t **)calloc(ret->onum, sizeof(uint8_t *));
  idx = 0;
  imsg(DPI_DEBUG_CIRCUIT, "# of Garbled Circuit Outputs: %d", ret->onum);
  for (i=0; i<ret->onum; i++)
  {
    ptr++;
    init = ptr;
    while (*ptr != ' ' && *ptr != '\n')
      ptr++;
    ret->olens[idx] = char_to_int((uint8_t *)init, ptr - init, 10);
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
    inum = char_to_int((uint8_t *)init, ptr - init, 10);

    ptr++;
    init = ptr;
    while (*ptr != ' ')
      ptr++;
    onum = char_to_int((uint8_t *)init, ptr - init, 10);
    ret->gates[idx] = init_gc_gate(idx, inum, onum);

    dmsg(DPI_DEBUG_CIRCUIT, "%d> line: %s", idx, line);
    dmsg(DPI_DEBUG_CIRCUIT, "%d> # of gate inputs: %d, # of gate outputs: %d", idx, inum, onum);

    for (i=0; i<inum; i++)
    {
      ptr++;
      init = ptr;
      while (*ptr != ' ')
        ptr++;
      tmp = char_to_int((uint8_t *)init, ptr - init, 10);
      add_gc_wire(ret->gates[idx], tmp, GARBLED_GATE_INPUT_WIRE);
    }

    for (i=0; i<onum; i++)
    {
      ptr++;
      init = ptr;
      while (*ptr != ' ')
        ptr++;
      tmp = char_to_int((uint8_t *)init, ptr - init, 10);
      add_gc_wire(ret->gates[idx], tmp, GARBLED_GATE_OUTPUT_WIRE);
    }

    ptr++;
    init = ptr;
    while (*ptr != '\n')
      ptr++;

    tmp = ptr - init;
    if (tmp == 3 && !strncmp(init, "XOR", tmp))
    {
      add_gc_type(ret->gates[idx], GARBLED_GATE_TYPE_XOR);
    }
    else if (tmp == 3 && !strncmp(init, "AND", tmp))
    {
      add_gc_type(ret->gates[idx], GARBLED_GATE_TYPE_AND);
    }
    else if (tmp == 3 && !strncmp(init, "INV", tmp))
    {
      add_gc_type(ret->gates[idx], GARBLED_GATE_TYPE_INV);
    }
    else if (tmp == 2 && !strncmp(init, "EQ", tmp))
    {
      add_gc_type(ret->gates[idx], GARBLED_GATE_TYPE_EQ);
    }
    else if (tmp == 3 && !strncmp(init, "EQW", tmp))
    {
      add_gc_type(ret->gates[idx], GARBLED_GATE_TYPE_EQW);
    }
    else if (tmp == 4 && !strncmp(init, "MAND", tmp))
    {
      add_gc_type(ret->gates[idx], GARBLED_GATE_TYPE_MAND);
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

  // find next gates per wire
  /*
  for (i=0; i<ret->wnum; i++)
  {
    memset(nexts, -1, MAX_NEXT_GATES * sizeof(int));
    nnum = 0;
    for (j=0; j<ret->gnum; j++)
    {
      for (x=0; x<ret->gates[j]->inum; x++)
      {
        if (i == ret->gates[j]->inputs[x])
          nexts[nnum++] = j;
      }
    }
    if (nnum > 0)
      add_gc_next_gates(ret->wires[i], nnum, nexts);
  }
  */

  for (i=0; i<ret->gnum; i++)
  {
    gate = ret->gates[i];
    for (j=0; j<gate->inum; j++)
    {
      wire = ret->wires[gate->inputs[j]];
      wire->nexts[wire->nnum++] = i;
    }
  }

  if (role == GARBLED_CIRCUIT_GARBLER)
  {
    imsg(DPI_DEBUG_CIRCUIT, "Now we generate the garbled table");
    for (i=0; i<ret->gnum; i++)
    {
      rc = generate_garbled_table(ret, i);
      if (rc != SUCCESS)
      {
        emsg("Generating garbled table failure");
        free_garbled_circuit(ret);
        ret = NULL;
        goto out;
      }
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
      case GARBLED_GATE_TYPE_XOR:
        printf("  - Type: XOR\n");
        break;
      case GARBLED_GATE_TYPE_AND:
        printf("  - Type: AND\n");
        break;
      case GARBLED_GATE_TYPE_INV:
        printf("  - Type: INV\n");
        break;
      case GARBLED_GATE_TYPE_MAND:
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
out:
  ffinish("ret: %p", ret);
  return ret;
}

void free_garbled_circuit(garbled_circuit_t *gc)
{
  fstart("gc: %p", gc);

  int i, j;

  if (gc)
  {
    for (i=0; i<gc->gnum; i++)
      free_gc_gate(gc->gates[i]);
    free(gc->gates);

    for (i=0; i<gc->wnum; i++)
      free_gc_wire(gc->wires[i]);
    free(gc->wires);

    for (i=0; i<gc->inum; i++)
    {
      for (j=0; j<sizeof(gc->ilens[i]); j++)
        free(gc->inputs[i][j]);
      free(gc->inputs[i]);
    }

    for (i=0; i<gc->onum; i++)
    {
      free(gc->obits[i]);
      free(gc->obytes[i]);
    }
    free(gc->olens);
    free(gc->obits);
    free(gc->obytes);
  }

  ffinish();
}

int generate_garbled_table(garbled_circuit_t *gc, int idx)
{
  fstart("gc: %p, idx: %d", gc, idx);
  assert(gc != NULL);
  assert(idx >= 0);

  int i, j, k, ret, oklen, ilen, olen, tlen;
  uint8_t bit[2], bout, ebit[2], ebout;
  uint8_t in[BUF_SIZE] = {0, };
  uint8_t tmp[BUF_SIZE] = {0, };
  uint8_t out[BUF_SIZE] = {0, };
  uint8_t *okey;
  uint8_t *ikeys[2];
  int iklens[2];
  fernet_t *fernet[2];
  gc_gate_t *gate;
  gc_wire_t *iwire[2]; // wire[0]: input for a, wire[1]: input for b
  gc_wire_t *owire;

  ret = FAILURE;
  gate = gc->gates[idx];
  assert(gate->type != GARBLED_GATE_TYPE_MAND);
  assert(gate->inum == 1 || gate->inum == 2);
  assert(gate->onum == 1);

  // TODO: Implement for the MAND gate later
  ebit[0] = 0;
  ebit[1] = 1;

  for (i=0; i<gate->inum; i++)
  {
    iwire[i] = get_gc_wire(gc, gate->inputs[i]);
    assert(iwire[i] != NULL);
  }
  owire = get_gc_wire(gc, gate->outputs[0]);

  if (gate->inum == 1)
  {
    for (i=0; i<2; i++)
    {
      bit[0] = xor(i, iwire[0]->pbit);
      
      switch(gate->type)
      {
        case GARBLED_GATE_TYPE_INV:
          bout = inv(bit[0]);
          break;

        default:
          emsg("Should not be happened");
          break;
      }

      memset(in, 0, BUF_SIZE);
      memset(tmp, 0, BUF_SIZE);
      memset(out, 0, BUF_SIZE);
      ilen = tlen = olen = 0;

      ebout = xor(bout, owire->pbit);
      ikeys[0] = iwire[0]->keys[bit[0]];
      iklens[0] = iwire[0]->klens[bit[0]];
      fernet[0] = init_fernet(ikeys[0], iklens[0]);

      okey = owire->keys[bout];    // output fernet key
      oklen = owire->klens[bout];  // output fernet key length
      
      memcpy(in, okey, oklen);
      ilen += oklen;
      *(in + oklen) = ebout;
      ilen++;

      fernet_encryption(fernet[0], in, ilen, out, &olen);
      gate->table[i][0] = (uint8_t *)calloc(olen, sizeof(uint8_t));
      memcpy(gate->table[i][0], out, olen);
      gate->emlen[i][0] = olen;
      gate->table[i][1] = gate->table[i][0];
      gate->emlen[i][1] = gate->emlen[i][1];

      dmsg(DPI_DEBUG_CIRCUIT, "Gate (%d): Table Entry [%d][%d]", gate->id, bit[0], 0);
      dprint(DPI_DEBUG_CIRCUIT, "gate->ikeys[0]", (ikeys[0]), 0, (iklens[0]), 16);
      dprint(DPI_DEBUG_CIRCUIT, "in", in, 0, ilen, 16);
      dprint(DPI_DEBUG_CIRCUIT, "emsg", out, 0, olen, 16);

      free_fernet(fernet[0]);
      
      dprint(DPI_DEBUG_CIRCUIT, "input", in, 0, ilen, 16);
      dprint(DPI_DEBUG_CIRCUIT, "output", out, 0, olen, 16);
    }
  }
  else if (gate->inum == 2)
  {
    for (i=0; i<2; i++)
    {
      for (j=0; j<2; j++)
      {
        bit[0] = xor(i, iwire[0]->pbit);
        bit[1] = xor(j, iwire[1]->pbit);
      
        switch(gate->type)
        {
          case GARBLED_GATE_TYPE_XOR:
            bout = xor(bit[0], bit[1]);
            break;

          case GARBLED_GATE_TYPE_AND:
            bout = and(bit[0], bit[1]);
            break;

          default:
            emsg("Should not be happened");
            break;
        }

        memset(in, 0, BUF_SIZE);
        memset(tmp, 0, BUF_SIZE);
        memset(out, 0, BUF_SIZE);
        ilen = tlen = olen = 0;

        ebout = xor(bout, owire->pbit);
        ikeys[0] = iwire[0]->keys[bit[0]];
        iklens[0] = iwire[0]->klens[bit[0]];
        fernet[0] = init_fernet(ikeys[0], iklens[0]);
        ikeys[1] = iwire[1]->keys[bit[1]];
        iklens[1] = iwire[1]->klens[bit[1]];
        fernet[1] = init_fernet(ikeys[1], iklens[1]);

        okey = owire->keys[bout];    // output fernet key
        oklen = owire->klens[bout];  // output fernet key length
      
        memcpy(in, okey, oklen);
        ilen += oklen;
        *(in + oklen) = ebout;
        ilen++;

        fernet_encryption(fernet[1], in, ilen, tmp, &tlen);
        fernet_encryption(fernet[0], tmp, tlen, out, &olen);
        gate->table[i][j] = (uint8_t *)calloc(olen, sizeof(uint8_t));
        memcpy(gate->table[i][j], out, olen);
        gate->emlen[i][j] = olen;

        dmsg(DPI_DEBUG_CIRCUIT, "Gate (%d): Table Entry [%d][%d]", gate->id, bit[0], bit[1]);
        dprint(DPI_DEBUG_CIRCUIT, "gate->ikeys[0]", (ikeys[0]), 0, (iklens[0]), 16);
        dprint(DPI_DEBUG_CIRCUIT, "gate->ikeys[1]", (ikeys[1]), 0, (iklens[1]), 16);
        dprint(DPI_DEBUG_CIRCUIT, "in", in, 0, ilen, 16);
        dprint(DPI_DEBUG_CIRCUIT, "tmp", tmp, 0, tlen, 16);
        dprint(DPI_DEBUG_CIRCUIT, "emsg", out, 0, olen, 16);

        free_fernet(fernet[0]);
        free_fernet(fernet[1]);
      
        dmsg(DPI_DEBUG_CIRCUIT, "bit[0]: %u, bit[1]: %u, bout: %u, ebit[0]: %u, ebit[1]: %u, ebout: %u", bit[0], bit[1], bout, ebit[0], ebit[1], ebout);
        dprint(DPI_DEBUG_CIRCUIT, "input", in, 0, ilen, 16);
        dprint(DPI_DEBUG_CIRCUIT, "output", out, 0, olen, 16);
      }
    }
  }

  ret = SUCCESS;
  ffinish("ret: %d", ret);
  return ret;
}

/**
 * @brief allocate the memory for the gate queue
 */
gc_gateq_t *init_gc_gateq(void)
{
  fstart();

  gc_gateq_t *ret;
  ret = (gc_gateq_t *)calloc(1, sizeof(gc_gateq_t));

  ffinish("ret: %p", ret);
  return ret;
}

/**
 * @brief Deallocate the memory used for the gate queue
 * @param gateq the gate queue
 */
void free_gc_gateq(gc_gateq_t *gateq)
{
  fstart("gateq: %p", gateq);

  int i;
  gc_gateq_entry_t *curr, *next;
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

gc_wire_t *init_gc_wire(int id, int role)
{
  fstart("id: %d, role: %d", id);
  assert(role == GARBLED_CIRCUIT_GARBLER || role == GARBLED_CIRCUIT_EVALUATOR);

  gc_wire_t *ret;
  int i, rc;

  ret = (gc_wire_t *)calloc(1, sizeof(gc_wire_t));
  if (!ret) goto out;

  ret->id = id; // Wire ID

  if (role == GARBLED_CIRCUIT_GARBLER)
  {
    ret->pbit = rand() % 2; // Pbit
    // Key is indexed by the "not-encrypted" bit

    // Generate the key pair for the wire
    for (i=0; i<2; i++)
    {
      rc = fernet_generate_key(ret->keys[i], &(ret->klens[i]));
      if (rc != SUCCESS)
      {
        free(ret);
        ret = NULL;
        goto out;
      }
    }
    dmsg(DPI_DEBUG_CIRCUIT, "Wire (%d): Pbit: %d", ret->id, ret->pbit);
    dprint(DPI_DEBUG_CIRCUIT, "key[0]", (ret->keys[0]), 0, (ret->klens[0]), 16);
    dprint(DPI_DEBUG_CIRCUIT, "key[1]", (ret->keys[1]), 0, (ret->klens[1]), 16);
  }

  memset(ret->nexts, 0x0, MAX_NEXT_GATES);

out:
  ffinish("ret: %p", ret);
  return ret;
}

void free_gc_wire(gc_wire_t *wire)
{
  fstart("wire: %p", wire);

  if (wire)
  {
    free(wire);
  }

  ffinish();
}

gc_gate_t *init_gc_gate(int id, uint16_t inum, uint16_t onum)
{
  fstart("inum: %d, onum: %d", inum, onum);
  assert(inum > 0);
  assert(onum > 0);

  gc_gate_t *ret;
  ret = (gc_gate_t *)calloc(1, sizeof(gc_gate_t));
  ret->type = -1;
  ret->id = id;
  ret->inum = inum;
  ret->inputs = (uint16_t *)calloc(inum, sizeof(uint16_t));
  ret->ikeys = (uint8_t **)calloc(inum, sizeof(uint8_t *));
  ret->iklens = (int *)calloc(inum, sizeof(int *));
  ret->ivalues = (uint8_t *)calloc(inum, sizeof(uint8_t));
  ret->enabled = (uint8_t *)calloc(inum, sizeof(uint8_t));
  ret->onum = onum;
  ret->outputs = (uint16_t *)calloc(onum, sizeof(uint16_t));

  ffinish("ret: %p", ret);
  return ret;
}

void add_gc_type(gc_gate_t *gate, uint8_t type)
{
  fstart("type: %u", type);

  gate->type = type;

  ffinish();
}

void add_gc_wire(gc_gate_t *gate, uint16_t widx, uint8_t is_output)
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
void add_gc_next_gates(gc_wire_t *wire, int nnum, int *nexts)
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

int check_gc_gate_is_ready(garbled_circuit_t *gc, gc_gate_t *gate)
{
  fstart("gc: %p, gate: %p", gc, gate);
  assert(gc != NULL);
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

void free_gc_gate(gc_gate_t *gate)
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

gc_wire_t *get_gc_wire(garbled_circuit_t *gc, int idx)
{
  fstart("gc: %p, idx: %d", gc, idx);
  assert(gc != NULL);
  
  gc_wire_t *ret;
  ret = gc->wires[idx];

  ffinish("ret: %p", ret);
  return ret;
}

int get_gc_wire_value(garbled_circuit_t *gc, int idx)
{
  fstart("gc: %p, idx: %d", gc, idx);
  assert(gc != NULL);

  int ret;
  ret = xor(gc->wires[idx]->value, gc->wires[idx]->pbit);
  dmsg(DPI_DEBUG_CIRCUIT, "Wire (%d): Value: %d, Pbit: %d, Return: %d", idx, (gc->wires[idx]->value), (gc->wires[idx]->pbit), ret);

  ffinish("ret: %d", ret);
  return ret;
}

int get_gc_wire_enabled(garbled_circuit_t *gc, int idx)
{
  fstart("gc: %p, idx: %d", gc, idx);
  assert(gc != NULL);

  int ret;
  ret = gc->wires[idx]->enabled;

  ffinish("ret: %d", ret);
  return ret;
}

void set_gc_wire_value(garbled_circuit_t *gc, int idx, uint8_t *msg, int mlen)
{
  fstart("gc: %p, idx: %d, msg: %p, mlen: %d", gc, idx, msg, mlen);
  assert(gc != NULL);
  assert(idx >= 0);
  assert(msg != NULL);
  assert(mlen > 0);
  assert(mlen == FERNET_ENCODED_KEY_BYTES + 1);

  int i, j;
  gc_wire_t *wire;
  gc_gate_t *gate;
  wire = gc->wires[idx];

  wire->enabled = 1;
  wire->value = *(msg + mlen - 1);
  memcpy(wire->keys[wire->value], msg, mlen - 1);
  wire->klens[wire->value] = FERNET_ENCODED_KEY_BYTES;

  for (i=0; i<wire->nnum; i++)
  {
    gate = gc->gates[wire->nexts[i]];
    for (j=0; j<gate->inum; j++)
    {
      if (wire->id == gate->inputs[j])
      {
        gate->iklens[j] = wire->klens[wire->value];
        gate->ikeys[j] = (uint8_t *)calloc(wire->klens[wire->value], sizeof(uint8_t));
        memcpy(gate->ikeys[j], wire->keys[wire->value], wire->klens[wire->value]);
        gate->ivalues[j] = wire->value;
        gate->enabled[j] = 1;
      }
    }
  }

  dmsg(DPI_DEBUG_CIRCUIT, "Wire (%d): Value: %d", wire->id, wire->value);

  ffinish();
}

/**
 * @brief Add the circuit input to the circuit (the input is added in bits)
 * @param circuit the circuit
 * @param input the input (in bytes)
 * @param input ilen the length of the input (in bytes)
 */
void add_gc_input(garbled_circuit_t *gc, uint8_t *input, int ilen)
{
  fstart("gc: %p, input: %p, ilen: %d", gc, input, ilen);
  assert(gc != NULL);
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
    if (gc->type == GARBLED_CIRCUIT_BRISTOL_AES_128)
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

  gc->inputs[gc->iset++] = bits;
  assert(gc->iset <= gc->inum);

  ffinish();
}

/**
 * @brief Prepare the circuit to be processed. Add ready gates to the gate queue and check inputs
 * @param circuit the circuit
 */
void prepare_gc_operation(garbled_circuit_t *gc)
{
  fstart("gc: %p", gc);
  assert(gc != NULL);

  int i, j, idx, inum, cnt;

  inum = gc->inum;
  idx = 0;
  cnt = 0;

  // check if the inputs are all set
  assert(inum == gc->iset);

  // move input bits to the circuit
  for (i=0; i<inum; i++)
  {
    for (j=0; j<gc->ilens[i]; j++)
      set_gc_wire_value(gc, idx+j, gc->inputs[i][j], gc->ilens[i][j]);
    idx += gc->ilens[i];
  }

#ifdef CIRCUIT_DEBUG
  idx = 0;
  for (i=0; i<inum; i++)
  {
    for (j=0; j<gc->ilens[i]; j++)
    {
      printf("Wire (%d): Value: %d\n", idx+j, get_gc_wire_value(gc, idx+j));
    }
    idx += gc->ilens[i];
  }

  uint8_t tmp[16];
  printf("Key in Circuit:");
  for (i=0; i<8; i++)
    tmp[i] = gc->wires[i]->value;
  for (i=0; i<8; i+=8)
    printf("%02x ", bit_to_byte(tmp, 8, i));
  printf("\n");

  printf("Input in Circuit:");
  for (i=8; i<16; i++)
    tmp[i-1] = gc->wires[i]->value;
  for (i=8; i<16; i+=8)
    printf("%02x ", bit_to_byte(tmp, 8, i));
  printf("\n");
#endif /* CIRCUIT_DEBUG */

  ffinish();
}

int gc_gate_operation(garbled_circuit_t *gc, int idx)
{
  fstart("gc: %p, idx: %d", gc, idx);
  assert(gc != NULL);
  assert(idx >= 0);

  int i, ret, mlen, emlen, tlen;
  gc_gate_t *gate;
  fernet_t *fernet[2];
  uint8_t ebit[2];
  uint8_t *emsg;
  uint8_t msg[BUF_SIZE] = {0, };
  uint8_t tmp[BUF_SIZE] = {0, };

  ret = FAILURE;
  gate = gc->gates[idx];
  assert(gate->inum == 1 || gate->inum == 2);
  assert(gate->onum == 1);

  for (i=0; i<gate->inum; i++)
  {
    ebit[i] = gate->ivalues[i];
    fernet[i] = init_fernet(gate->ikeys[i], gate->iklens[i]);
  }

  dmsg(DPI_DEBUG_CIRCUIT, "Gate (%d): Type: %d, Table Entry [%d][%d]", idx, (gate->type), ebit[0], ebit[1]);
  dprint(DPI_DEBUG_CIRCUIT, "gate->ikeys[0]", (gate->ikeys[0]), 0, (gate->iklens[0]), 16);
  dprint(DPI_DEBUG_CIRCUIT, "gate->ikeys[1]", (gate->ikeys[1]), 0, (gate->iklens[1]), 16);
  if (gate->inum == 1)
    ebit[1] = 0;
  emsg = gate->table[ebit[0]][ebit[1]];
  emlen = gate->emlen[ebit[0]][ebit[1]];
  dprint(DPI_DEBUG_CIRCUIT, "emsg", emsg, 0, emlen, 16);

  if (gate->inum == 1)
  {
    fernet_decryption(fernet[0], emsg, emlen, msg, &mlen);
  }
  else if (gate->inum == 2)
  {
    fernet_decryption(fernet[0], emsg, emlen, tmp, &tlen);
    fernet_decryption(fernet[1], tmp, tlen, msg, &mlen);
  }

  set_gc_wire_value(gc, gate->outputs[0], msg, mlen);
  dmsg(DPI_DEBUG_CIRCUIT, "Output set to Gate (%d) with the encrypted value: %d", (gate->outputs[0]), *(msg + mlen - 1));

  ret = SUCCESS;
  ffinish("ret: %d", ret);
  return ret;
}

int evaluate_garbled_circuit(garbled_circuit_t *gc)
{
  fstart("gc: %p", gc);
  assert(gc != NULL);

  int i, j, rc, ret, tmp, sidx, eidx;
  uint8_t buf[1024] = {0, };
  uint8_t *tout;

  ret = FAILURE;
  for (i=0; i<gc->gnum; i++)
  {
    rc = gc_gate_operation(gc, i);
    if (rc != SUCCESS) goto out;
  }

  tmp = 0;
  for (i=0; i<gc->onum; i++)
    tmp += gc->olens[i];

  sidx = gc->wnum - tmp;
  for (i=0; i<gc->onum; i++)
  {
    eidx = sidx + gc->olens[i];
    tout = (uint8_t *)calloc(gc->olens[i], sizeof(uint8_t));
    for (j=0; sidx+j<eidx; j++)
      tout[j] = get_gc_wire_value(gc, sidx+j);
    for (j=0; j<gc->olens[i]; j++)
    {
      if (gc->type == GARBLED_CIRCUIT_BRISTOL_AES_128)
        gc->obits[i][gc->olens[i]-1-j] = tout[j];
      else
        gc->obits[i][j] = tout[j];
    }
    sidx = eidx;
  }

  for (i=0; i<gc->onum; i++)
  {
    for (j=0; j<gc->olens[i]; j++)
      buf[j] = gc->obits[i][j];
    tmp = gc->olens[i] / 8;
    for (j=0; j<tmp; j++)
      gc->obytes[i][j] = bit_to_byte(buf, 8, 8*j);
  }

out:
  ffinish("ret: %d", ret);
  return ret;
}

uint8_t *get_gc_output_bits(garbled_circuit_t *gc, int idx, int *olen)
{
  fstart("gc: %p, olen: %p", gc, olen);
  assert(gc != NULL);
  assert(olen != NULL);
  assert(idx >= 0 && idx <= gc->onum);

  uint8_t *ret;
  ret = gc->obits[idx];
  *olen = gc->olens[idx];

  ffinish("ret: %p", ret);
  return ret;
}

uint8_t *get_gc_output_bytes(garbled_circuit_t *gc, int idx, int *olen)
{
  fstart("gc: %p, olen: %p", gc, olen);
  assert(gc != NULL);
  assert(olen != NULL);
  assert(idx >= 0 && idx <= gc->onum);

  uint8_t *ret;
  ret = gc->obytes[idx];
  *olen = gc->olens[idx] / 8;

  ffinish("ret: %p", ret);
  return ret;
}

