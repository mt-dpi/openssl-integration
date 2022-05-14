#include <string.h>
#include <unistd.h>
#include <dpi/defines.h>
#include <sys/socket.h>
#include "gc_protocol.h"
#include "garbled_circuit.h"
#include "bit_op.h"

int send_garbled_circuit_info(int sock, garbled_circuit_t *gc)
{
  fstart("sock: %d, gc: %p", sock, gc);
  assert(gc != NULL);

  uint8_t cid;
  uint8_t buf[BUF_SIZE] = {0, };
  uint8_t *p;
  int i, j, k, ret, len, sent, sid, eid, tbs, offset;
  gc_gate_t *gate;
  gc_wire_t *wire;

  ret = FAILURE;
  cid = gc->type;

  // Sending the circuit ID
  sent = write(sock, &cid, 1);
  assert(sent == 1);

  // Sending the garbled tables
  // gate id (2 bytes) || len (2 bytes) || msg[0][0] || len (2 bytes) || msg[0][1] 
  // || len (2 bytes) || msg[1][0] || len (2 bytes) || msg[1][1]
  for (i=0; i<gc->gnum; i++)
  {
    dmsg(DPI_DEBUG_CIRCUIT, "===== Gate %d =====", i);
    p = buf;
    gate = gc->gates[i];
    assert(i == gate->id);
    VAR_TO_PTR_2BYTES(i, p);
    for (j=0; j<2; j++)
      for (k=0; k<2; k++)
      {
        VAR_TO_PTR_2BYTES((gate->emlen[j][k]), p);
        memcpy(p, gate->table[j][k], gate->emlen[j][k]);
        p += gate->emlen[j][k];
        dmsg(DPI_DEBUG_CIRCUIT, "Gate (%d): Table Entry [%d][%d]", i, j, k);
        dprint(DPI_DEBUG_CIRCUIT, "Table Entry", (gate->table[j][k]), 0, (gate->emlen[j][k]), 16);
      }
    tbs = p-buf;
    offset = 0;
    while (offset < tbs)
    {
      sent = write(sock, buf+offset, tbs-offset);
      offset += sent;
    }
    assert(offset == (p-buf));
  }
  dmsg(DPI_DEBUG_CIRCUIT, "");

  // Sending the pbit per output wire
  // wire id (2 bytes) || pbit (1 byte)
  
  // TODO: Generalize below (the current version only deals with the one output
  eid = gc->wnum;
  sid = eid - gc->olens[0];

  for (i=sid; i<eid; i++)
  {
    wire = gc->wires[i];
    dmsg(DPI_DEBUG_CIRCUIT, "Wire (%d): Pbit: %d", i, wire->pbit);
    p = buf;
    VAR_TO_PTR_2BYTES(i, p);
    *(p++) = wire->pbit;
    tbs = p-buf;
    offset = 0;
    while (offset < tbs)
    {
      sent = write(sock, buf+offset, tbs-offset);
      offset += sent;
    }
    assert(offset == (p-buf));
  }

  ret = SUCCESS;

out:
  ffinish("ret: %d", ret);
  return ret;
}

garbled_circuit_t *receive_garbled_circuit_info(int sock)
{
  fstart("sock: %d", sock);

  garbled_circuit_t *ret;
  uint8_t buf[BUF_SIZE] = {0, };
  uint8_t *p, *table;
  uint16_t id, emlen;
  int i, j, k, cid, rcvd, tbr, offset;
  const char *cname;
  gc_gate_t *gate;
  gc_wire_t *wire;

  rcvd = read(sock, buf, 1);
  p = buf;
  cid = *(p++);

  switch (cid)
  {
    case GARBLED_CIRCUIT_BRISTOL_AES_128:
      cname = "../circuit/aes_128_basic.txt";
      break;

    case GARBLED_CIRCUIT_BRISTOL_AES_192:
      cname = "../circuit/aes_192_basic.txt";
      break;

    case GARBLED_CIRCUIT_BRISTOL_AES_256:
      cname = "../circuit/aes_256_basic.txt";
      break;

    case GARBLED_CIRCUIT_TEST_1:
      cname = "../circuit/test1.txt";
      break;

    case GARBLED_CIRCUIT_TEST_2:
      cname = "../circuit/test2.txt";
      break;

    default:
      break;
  }

  ret = init_garbled_circuit(cname, GARBLED_CIRCUIT_EVALUATOR); 

  for (i=0; i<ret->gnum; i++)
  {
    rcvd = read(sock, buf, 2);
    assert(rcvd == 2);
    p = buf;
    PTR_TO_VAR_2BYTES(p, id);
    assert(i == id);

    imsg(DPI_DEBUG_CIRCUIT, "===== Gate %d =====", id);
    gate = ret->gates[id];
    table = gate->table;

    for (j=0; j<2; j++)
      for (k=0; k<2; k++)
      {
        rcvd = read(sock, buf, 2);
        assert(rcvd == 2);
        p = buf;
        PTR_TO_VAR_2BYTES(p, emlen);
        gate->emlen[j][k] = emlen;
        gate->table[j][k] = (uint8_t *)calloc(emlen, sizeof(uint8_t));
        
        tbr = emlen;
        offset = 0;
        while (offset < tbr)
        {
          rcvd = read(sock, (gate->table[j][k])+offset, emlen-offset);
          offset += rcvd;
        }
        assert(offset == tbr);

        dprint(DPI_DEBUG_CIRCUIT, "Table Entry", (gate->table[j][k]), 0, (gate->emlen[j][k]), 16);
      }
    dmsg(DPI_DEBUG_CIRCUIT, "");
  }

  for (i=0; i<ret->olens[0]; i++)
  {
    rcvd = read(sock, buf, 3);
    assert(rcvd == 3);
    p = buf;
    PTR_TO_VAR_2BYTES(p, id);

    wire = ret->wires[id];
    wire->pbit = *p;

    imsg(DPI_DEBUG_CIRCUIT, "Wire (%d): Pbit: %d", id, wire->pbit);
  }

  ffinish("ret: %p", ret);
  return ret;
}

int send_confirmation(int sock)
{
  fstart("sock: %d", sock);

  int ret, sent;
  uint8_t confirm;
  confirm = 1;

  ret = FAILURE;
  sent = write(sock, &confirm, 1);
  
  if (sent != 1)
  {
    emsg("Sending the confirmation error");
    goto out;
  }

  imsg(DPI_DEBUG_CIRCUIT, "Sending the confirmation success");
  ret = SUCCESS;

out:
  ffinish("ret: %d", ret);
  return ret;
}

int receive_confirmation(int sock)
{
  fstart("sock: %d", sock);

  int ret, rcvd;
  uint8_t confirm;

  ret = FAILURE;
  rcvd = read(sock, &confirm, 1);

  if (rcvd != 1)
  {
    emsg("Receiving the confirmation error");
    goto out;
  }

  if (confirm != 1)
  {
    emsg("Confirmation error");
    goto out;
  }

  imsg(DPI_DEBUG_CIRCUIT, "Receive the confirmation correctly");
  ret = SUCCESS;

out:
  ffinish("ret: %d", ret);
  return ret;
}

int send_encrypted_input_and_keys(int sock, garbled_circuit_t *gc, ot_t *ot, 
    uint8_t *input, int ilen)
{
  fstart("sock: %d, gc: %p, ot: %p, input: %p, ilen: %d", sock, gc, ot, input, ilen);
  assert(gc != NULL);
  assert(ot != NULL);

  int i, ret, blen, bits_per_byte, klen, sent, rcvd, idx, sidx, tbs, offset;
  int mlen[2];
  uint8_t *p, *key;
  uint8_t value;
  uint8_t buf[BUF_SIZE] = {0, };
  uint8_t bits[BUF_SIZE] = {0, };
  uint8_t msg[2][BUF_SIZE];
  uint8_t tmp[BUF_SIZE] = {0, };
  uint16_t id;
  gc_wire_t *wire;

  ret = FAILURE;
  bits_per_byte = 8;

  byte_to_bit(input, bits_per_byte, ilen, tmp);
  blen = bits_per_byte * ilen;
  dmsg(DPI_DEBUG_CIRCUIT, "Send Garbler's Input to Evaluator (%d bits)", blen);

  for (i=0; i<blen; i++)
  {
    if (gc->type == GARBLED_CIRCUIT_BRISTOL_AES_128)
      bits[blen-1-i] = tmp[i];
    else
      bits[i] = tmp[i];
  }

  p = buf;
  VAR_TO_PTR_4BYTES(blen, p);
  tbs = p-buf;
  offset = 0;
  while (offset < tbs)
  {
    sent = write(sock, buf+offset, tbs-offset);
    offset += sent;
  }
  assert(offset == (p-buf));

  for (i=0; i<blen; i++)
  {
    wire = gc->wires[i];
    id = wire->id;
    value = xor(wire->pbit, bits[i]);
    key = wire->keys[bits[i]];
    klen = wire->klens[bits[i]];
    //key = wire->keys[value];
    //klen = wire->klens[value];

    // ID (2 bytes) || klen (4 bytes) || key || value (1 byte)
    p = buf;
    VAR_TO_PTR_2BYTES(id, p);
    VAR_TO_PTR_4BYTES(klen, p);
    memcpy(p, key, klen);
    p += klen;
    *(p++) = value;

    dmsg(DPI_DEBUG_CIRCUIT, "Wire (%d): Input: %d, Pbit: %d, Encrypted Value: %d", id, bits[i], wire->pbit, value);
    dprint(DPI_DEBUG_CIRCUIT, "Key", key, 0, klen, 16);
    tbs = p-buf;
    offset = 0;
    while (offset < tbs)
    {
      sent = write(sock, buf+offset, tbs-offset);
      offset += sent;
    }
    assert(offset == (p-buf));
  }

  p = buf;
  rcvd = read(sock, p, 4);
  assert(rcvd == 4);
  PTR_TO_VAR_4BYTES(p, blen);
  rcvd = read(sock, p, 4);
  assert(rcvd == 4);
  PTR_TO_VAR_4BYTES(p, sidx);

  for (i=sidx; i<sidx+blen; i++)
  {
    wire = gc->wires[i];
    id = wire->id;
    p = buf;
    VAR_TO_PTR_2BYTES(id, p);
    tbs = p-buf;
    offset = 0;
    while (offset < tbs)
    {
      sent = write(sock, buf+offset, tbs-offset);
      offset += sent;
    }
    assert(offset == (p-buf));
    dmsg(DPI_DEBUG_CIRCUIT,  "Wire [%d]: ID: %d", i, wire->id);

    // msg0: klen (4 bytes) || key || value (= 0 ^ wire->pbit) (1 byte)
    value = xor(wire->pbit, 0);
    key = wire->keys[0];
    klen = wire->klens[0];
    //key = wire->keys[value];
    //klen = wire->klens[value];
    //idx = wire->pbit;
    //p = msg[idx];
    p = msg[0];
    VAR_TO_PTR_4BYTES(klen, p);
    memcpy(p, key, klen);
    p += klen;
    *(p++) = value;
    //mlen[idx] = p - msg[idx];
    mlen[0] = p - msg[0];

    // msg1: klen (4 bytes) || key || value (= 1 ^ wire->pbit) (1 byte)
    value = xor(wire->pbit, 1);
    key = wire->keys[1];
    klen = wire->klens[1];
    //key = wire->keys[value];
    //klen = wire->klens[value];
    //idx = (idx + 1) % 2;
    //p = msg[idx];
    p = msg[1];
    VAR_TO_PTR_4BYTES(klen, p);
    memcpy(p, key, klen);
    p += klen;
    *(p++) = value;
    //mlen[idx] = p - msg[idx];
    mlen[1] = p - msg[1];

    send_ot_message(sock, ot, msg[0], mlen[0], msg[1], mlen[1]);
    dprint(DPI_DEBUG_CIRCUIT, "Message 0", msg[0], 0, mlen[0], 16);
    dprint(DPI_DEBUG_CIRCUIT, "Message 1", msg[1], 0, mlen[1], 16);
  }

  ret = SUCCESS;
  ffinish("ret: %d", ret);
  return ret;
}

int receive_encrypted_input_and_keys(int sock, garbled_circuit_t *gc, ot_t *ot, 
    uint8_t *input, int ilen)
{
  fstart("sock: %d, gc: %p, ot: %p, input: %p, ilen: %d", sock, gc, ot, input, ilen);
  assert(gc != NULL);
  assert(ot != NULL);

  int i, b, ret, sent, rcvd, mlen, klen, inum, blen, bits_per_byte, sidx, tbs, tbr, offset;
  uint8_t value;
  uint8_t buf[BUF_SIZE] = {0, };
  uint8_t bits[BUF_SIZE] = {0, };
  uint8_t tmp[BUF_SIZE] = {0, };
  uint8_t *p, *msg;
  uint16_t id;
  gc_wire_t *wire;

  ret = FAILURE;
  bits_per_byte = 8;
  
  p = buf;
  rcvd = read(sock, p, 4);
  assert(rcvd == 4);
  PTR_TO_VAR_4BYTES(p, inum);

  imsg(DPI_DEBUG_CIRCUIT, "Receive Encrypted Input (%d bits)", inum);
  for (i=0; i<inum; i++)
  {
    p = buf;
    rcvd = read(sock, p, 2);
    assert(rcvd == 2);
    PTR_TO_VAR_2BYTES(p, id);

    wire = gc->wires[id];

    rcvd = read(sock, p, 4);
    assert(rcvd == 4);
    PTR_TO_VAR_4BYTES(p, klen);
    //wire->klens[wire->value] = klen;
    //assert(klen <= FERNET_ENCODED_KEY_BYTES);

    msg = p;
    tbr = klen;
    offset = 0;
    while (offset < tbr)
    {
      rcvd = read(sock, p + offset, klen - offset);
      offset += tbr;
    }
    assert(offset == tbr);
    //memcpy(wire->keys[wire->value], p, klen);
    p += klen;

    rcvd = read(sock, p, 1);
    assert(rcvd == 1);
    wire->value = *(p++);

    mlen = p - msg;
    set_gc_wire_value(gc, id, msg, mlen);

    dmsg(DPI_DEBUG_CIRCUIT, "Wire (%d): Value: %d", wire->id, wire->value);
    dprint(DPI_DEBUG_CIRCUIT, "Key", (wire->keys[wire->value]), 0, (wire->klens[wire->value]), 16);
  }

  dmsg(DPI_DEBUG_CIRCUIT, "Request Encrypted Input (%d bits)", blen);

  byte_to_bit(input, bits_per_byte, ilen, tmp);
  blen = ilen * bits_per_byte;
  for (i=0; i<blen; i++)
  {
    if (gc->type == GARBLED_CIRCUIT_BRISTOL_AES_128)
      bits[blen-1-i] = tmp[i];
    else
      bits[i] = tmp[i];
  }

  p = buf;
  VAR_TO_PTR_4BYTES(blen, p);
  sidx = inum;
  VAR_TO_PTR_4BYTES(sidx, p);
  tbs = p-buf;
  offset = 0;
  while (offset < tbs)
  {
    sent = write(sock, buf+offset, tbs-offset);
    offset += sent;
  }
  assert(sent == (p-buf));

  for (i=0; i<blen; i++)
  {
    p = buf;
    rcvd = read(sock, p, 2);
    assert(rcvd == 2);
    PTR_TO_VAR_2BYTES(p, id);
    
    wire = gc->wires[id];

    b = bits[i];
    receive_ot_message(sock, ot, b, p, &mlen);
    PTR_TO_VAR_4BYTES(p, klen);
    mlen -= 4;
    assert(mlen == klen + 1);
    set_gc_wire_value(gc, id, p, mlen);

    dmsg(DPI_DEBUG_CIRCUIT, "Wire (%d): Value: %d\n", wire->id, wire->value);
    dprint(DPI_DEBUG_CIRCUIT, "Key", (wire->keys[wire->value]), 0, (wire->klens[wire->value]), 16);
    
  }

  ret = SUCCESS;
  ffinish("ret: %d", ret);
  return ret;
}

int send_result(int sock, garbled_circuit_t *gc, ot_t *ot)
{
  fstart("sock: %d, gc: %p, ot: %p", sock, gc, ot);
  assert(gc != NULL);
  assert(ot != NULL);

  int ret, olen, sent, tbs, offset;
  uint8_t *output, *p;
  uint8_t buf[BUF_SIZE];
  ret = FAILURE;

  evaluate_garbled_circuit(gc);
  output = get_gc_output_bytes(gc, 0, &olen);

  iprint(DPI_DEBUG_CIRCUIT, "Result", output, 0, olen, 16);
  p = buf;
  VAR_TO_PTR_4BYTES(olen, p);
  memcpy(p, output, olen);
  p += olen;
  tbs = p-buf;
  offset = 0;
  while (offset < tbs)
  {
    sent = write(sock, buf+offset, (p-buf)-offset);
    offset += sent;
  }
  assert(offset == (p-buf));

  ret = SUCCESS;
  ffinish("ret: %d", ret);
  return ret;
}

int receive_result(int sock, garbled_circuit_t *gc, ot_t *ot)
{
  fstart("sock: %d, gc: %p, ot: %p", sock, gc, ot);
  assert(gc != NULL);
  assert(ot != NULL);
    
  int ret, rcvd, olen, tbr, offset;
  uint8_t *p;
  uint8_t buf[BUF_SIZE];
  ret = FAILURE;

  p = buf;
  tbr = 4;
  offset = 0;
  while (offset < tbr)
  {
    rcvd = read(sock, p+offset, 4-offset);
    offset += rcvd;
  }
  assert(offset == tbr);
  PTR_TO_VAR_4BYTES(p, olen);
  imsg(DPI_DEBUG_CIRCUIT, "Output Length: %d", olen);

  tbr = olen;
  offset = 0;
  while (offset < tbr)
  {
    rcvd = read(sock, p+offset, olen-offset);
    offset += rcvd;
  }
  assert(offset == tbr);
  iprint(DPI_DEBUG_CIRCUIT, "Output", p, 0, olen, 16);

  ret = SUCCESS;
  ffinish("ret: %d", ret);
  return ret;
}
