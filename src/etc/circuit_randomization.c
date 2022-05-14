#include <dpi/dpi.h>
#include <dpi/debug.h>
#include <dpi/defines.h>
#include <dpi/circuit_randomization.h>

#include <stdint.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <openssl/evp.h>
#include <time.h>
#include <sys/time.h>

#include "bit_op.h"

#define SECURITY_PARAMETER 1

int verify(uint8_t *a, uint8_t *b, int len)
{
  int ret, i;
  ret = TRUE;

  dprint(DPI_DEBUG_INIT, "a", a, 0, len, len);
  dprint(DPI_DEBUG_INIT, "b", b, 0, len, len);

  for (i=0; i<len; i++)
  {
    if (a[i] != b[i])
    {
      ret = FALSE;
      break;
    }
  }

  return ret;
}

int fernet_random_ot(int role, int sock, uint8_t *a, uint8_t *b, uint8_t *c)
{
  fstart("role: %d, sock: %d, a: %p, b: %p, c: %p", role, sock, a, b, c);
  assert(a != NULL);
  assert(b != NULL);
  assert(c != NULL);

  int ret;
  ret = SUCCESS;

  *a = 0;
  *b = 0;
  *c = 0;

  ffinish("ret: %d", ret);
  return ret;
}

int generate_certificate(uint8_t *keyword, int klen, uint8_t *pkey,
    uint8_t *random, int rlen, uint8_t *cert, int *clen)
{
  fstart("keyword: %p, klen: %d, pkey: %p, pklen: %d, random: %p, rlen: %d, cert: %p, clen: %p", keyword, klen, pkey, pklen, random, rlen, cert, clen);

  int i, ret, bsize;
  EVP_CIPHER_CTX *ectx;
  uint8_t input[16] = {0, };

  ret = SUCCESS;
  bsize = 16;

  ectx = EVP_CIPHER_CTX_new();
  EVP_EncryptInit_ex(ectx, EVP_aes_128_ecb(), NULL, pkey, NULL);
  memcpy(input, keyword, klen);
  EVP_EncryptUpdate(ectx, cert, clen, input, bsize);

  for (i=0; i<bsize; i++)
    cert[i] = cert[i] ^ random[i];

  EVP_CIPHER_CTX_free(ectx);
  ffinish("ret: %d", ret);
  return ret;
}

void proceed_cr_and_gates(int role, int sock, circuit_t *circuit, uint8_t a, uint8_t b, uint8_t c)
{
  fstart("role: %d, sock: %d, circuit: %p, a: %u, b: %u, c: %u", role, sock, circuit, a, b, c);
  assert(sock > 0);
  assert(circuit != NULL);

  int i, j, k, num, sent, rcvd, tbs, tbr, offset, slen, rlen;
  uint8_t x, y, z, xa, yb, tmp;
  uint8_t xatmp1, ybtmp1, xatmp2, ybtmp2;
  uint8_t sbuf[BUF_SIZE];
  uint8_t rbuf[BUF_SIZE];
  uint16_t sid, rid;
  gate_t *gate, *ngate;
  wire_t *wire;
  gateq_t *gateq;
  uint8_t *p, *q;

  gateq = circuit->gateq;
  num = gateq->num;

  p = sbuf + 2;
  for (i=0; i<num; i++)
  {
    gate = dequeue(circuit, FALSE, FALSE);
    VAR_TO_PTR_2BYTES((gate->id), p);
   
    x = gate->ivalues[0];
    y = gate->ivalues[1];

    *(p++) = xor(x, a); // (xi + ai)
    *(p++) = xor(y, b); // (yi + bi) 
  }
  slen = p-sbuf;
  p = sbuf;
  VAR_TO_PTR_2BYTES(slen, p);

  if (role == DPI_ROLE_MIDDLEBOX)
  {
    tbs = slen + 2;
    offset = 0;
    while (offset < tbs)
    {
      sent = write(sock, sbuf+offset, tbs-offset);
      offset += sent;
    }
    assert(offset == tbs);
    dprint(DPI_DEBUG_CIRCUIT, "Sent Values", sbuf, 0, tbs, 16);

    tbr = 2;
    offset = 0;
    while (offset < tbr)
    {
      rcvd = read(sock, rbuf+offset, tbr-offset);
      offset += rcvd;
    }
    assert(offset == tbr);

    p = rbuf;
    PTR_TO_VAR_2BYTES(p, rlen);
    tbr = rlen;
    offset = 0;
    while (offset < tbr)
    {
      rcvd = read(sock, rbuf+offset, tbr-offset);
      offset += rcvd;
    }
    assert(offset == tbr);
    dprint(DPI_DEBUG_CIRCUIT, "Received Values", rbuf, 0, tbr, 16);
  }
  else if (role == DPI_ROLE_CLIENT)
  {
    tbr = 2;
    offset = 0;
    while (offset < tbr)
    {
      rcvd = read(sock, rbuf+offset, tbr-offset);
      offset += rcvd;
    }
    assert(offset == tbr);

    p = rbuf;
    PTR_TO_VAR_2BYTES(p, rlen);
    tbr = rlen;
    offset = 0;
    while (offset < tbr)
    {
      rcvd = read(sock, rbuf+offset, tbr-offset);
      offset += rcvd;
    }
    assert(offset == tbr);
    dprint(DPI_DEBUG_CIRCUIT, "Received Values", rbuf, 0, tbr, 16);

    tbs = slen + 2;
    offset = 0;
    while (offset < tbs)
    {
      sent = write(sock, sbuf+offset, tbs-offset);
      offset += sent;
    }
    assert(offset == tbs);
    dprint(DPI_DEBUG_CIRCUIT, "Sent Values", sbuf, 0, tbs, 16);
  }

  p = sbuf + 2;
  q = rbuf;
  for (i=0; i<num; i++)
  {
    PTR_TO_VAR_2BYTES(p, sid);
    PTR_TO_VAR_2BYTES(q, rid);
    assert(sid == rid);

    gate = circuit->gates[sid];
    xatmp1 = *(p++); // (x1 + a1)
    ybtmp1 = *(p++); // (y1 + b1)
    xatmp2 = *(q++); // (x2 + a2)
    ybtmp2 = *(q++); // (y2 + b2)
    dmsg(DPI_DEBUG_CIRCUIT, "Gate ID: %d, xa1: %u, xa2: %u, yb1: %u, yb2: %u", sid, xatmp1, xatmp2, ybtmp1, ybtmp2);
    xa = xor(xatmp1, xatmp2); // (x1 + x2 + a1 + a2) = (x + a)
    yb = xor(ybtmp1, ybtmp2); // (y1 + y2 + b1 + b2) = (y + b)

    if (role == DPI_ROLE_MIDDLEBOX) // a1, b1, c1
    {
      tmp = and(xa, yb); // (x + a) * (y + b)
      tmp = xor(tmp, inv(and(xa, b))); // (x+a)*(y+b) - (x+a)*b1
      tmp = xor(tmp, inv(and(yb, a))); // (x+a)*(y+b) - (x+a)*b1 - (y+b)*a1
      z = xor(tmp, c); // (x+a)*(y+b) - (x+a)*b1 - (y+b)*a1 + c1
    }
    else if (role == DPI_ROLE_CLIENT) // a2, b2, c2
    {
      tmp = inv(and(xa, b)); // -(x+a)*b2
      tmp = xor(tmp, inv(and(yb, a))); // -(x+a)*b2 -(y+b)*a2
      z = xor(tmp, c); // -(x+a)*b2 -(y+b)*a2 + c2
    }
    set_wire_value(circuit, gate->outputs[0], z);

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

int circuit_randomization(int role, int sock, uint8_t a, uint8_t b, uint8_t c, void *data)
{
  fstart("role: %d, sock: %d, a: %d, b: %d, c: %d, data: %p", role, sock, a, b, c, data);
  assert(sock > 0);

  int i, j, x, y, ret, cid, plen, mlen, blen, klen, olen, tmp, sidx, eidx;
  int sent, rcvd, offset, tbs, tbr;
  uint8_t *pkey, *msg, *key;
  uint8_t s, idx;
  const char *cname;
  uint8_t hval[16] = {0, };
  uint8_t zkey[16] = {0, };
  uint8_t bvals[SECURITY_PARAMETER] = {0, };
  uint8_t *rp_mb[SECURITY_PARAMETER] = {NULL, };
  uint8_t *rp_s[SECURITY_PARAMETER] = {NULL, };
  uint8_t *rps[SECURITY_PARAMETER] = {NULL, };
  uint8_t btmp[16] = {0, };
  uint8_t buf[BUF_SIZE] = {0, };
  uint8_t *p, *tout;
  int verified, chosen;
  circuit_t *circuit;
  mb_input_t *min;
  sender_input_t *sin;

  ret = SUCCESS;
  s = SECURITY_PARAMETER;
  min = NULL;
  sin = NULL;
  srand(time(NULL));

  if (role == DPI_ROLE_MIDDLEBOX)
  {
    min = (mb_input_t *)data;
    cid = min->cid;
    /*
    tbr = 4;
    offset = 0;
    while (offset < tbr)
    {
      rcvd = read(sock, buf+offset, tbr-offset);
      offset += rcvd;
    }
    p = buf;
    PTR_TO_VAR_4BYTES(p, cid);
    */

    switch (cid)
    {
      case MPC_CIRCUIT_BRISTOL_AES_128:
        cname = "../circuit/aes_128_basic.txt";
        break;

      case MPC_CIRCUIT_BRISTOL_AES_192:
        cname = "../circuit/aes_192_basic.txt";
        break;

      case MPC_CIRCUIT_BRISTOL_AES_256:
        cname = "../circuit/aes_256_basic.txt";
        break;

      case MPC_CIRCUIT_TEST_1:
        cname = "../circuit/test1.txt";
        break;

      case MPC_CIRCUIT_TEST_2:
        cname = "../circuit/test2.txt";
        break;

      case MPC_CIRCUIT_TEST_3:
        cname = "../circuit/test3.txt";
        break;

      default:
        cname = "../circuit/aes_128_basic.txt";
    }

    circuit = init_circuit(cname);
    set_circuit_role(circuit, MPC_CIRCUIT_RANDOMIZATION_FLIP);
    pkey = min->pkey;
    plen = min->plen;
    dmsg(DPI_DEBUG_INIT, "Middlebox >");
  }
  else if (role == DPI_ROLE_CLIENT)
  {
    sin = (sender_input_t *)data;
    circuit = init_circuit(sin->cname);
    set_circuit_role(circuit, MPC_CIRCUIT_RANDOMIZATION_NONE);
    cid = get_circuit_type(circuit);

    /*
    p = buf;
    VAR_TO_PTR_4BYTES(cid, p);
    
    tbs = p-buf;
    offset = 0;
    while (offset < tbs)
    {
      sent = write(sock, buf+offset, tbs-offset);
      offset += sent;
    }
    */

    pkey = sin->pkey;
    plen = sin->plen;
    dmsg(DPI_DEBUG_INIT, "Sender >");
  }
  
  switch (cid)
  {
    case MPC_CIRCUIT_BRISTOL_AES_128:
      blen = 16;
      break;

    case MPC_CIRCUIT_BRISTOL_AES_192:
      blen = 24;
      break;

    case MPC_CIRCUIT_BRISTOL_AES_256:
      blen = 32;
      break;
   
    case MPC_CIRCUIT_TEST_1:
    case MPC_CIRCUIT_TEST_2:
    case MPC_CIRCUIT_TEST_3:
      blen = 1;
      break;

    default:
      blen = 16;
  }

  msg = (uint8_t *)calloc(blen, sizeof(uint8_t));
  if (role == DPI_ROLE_MIDDLEBOX)
  {
    dmsg(DPI_DEBUG_INIT, "a1: %d", a);
    dmsg(DPI_DEBUG_INIT, "b1: %d", b);
    dmsg(DPI_DEBUG_INIT, "c1: %d", c);
    memcpy(msg, min->keyword, min->klen);
    mlen = min->klen;
  }
  else if (role == DPI_ROLE_CLIENT)
  {
    dmsg(DPI_DEBUG_INIT, "a2: %d", a);
    dmsg(DPI_DEBUG_INIT, "b2: %d", b);
    dmsg(DPI_DEBUG_INIT, "c2: %d", c);
  }

  add_input(circuit, pkey, plen);
  iprint(DPI_DEBUG_CIRCUIT, "Added Public AES Key", pkey, 0, plen, 16);

  // Repeat the folloiwng s times where s is a statistical security parameter. 
  // In the j-th repetition:
  for (j=0; j<s; j++)
  {
    if (role == DPI_ROLE_MIDDLEBOX)
    {
      key = zkey;
      change_input(circuit, 1, msg, blen);
      iprint(DPI_DEBUG_CIRCUIT, "Added Keyword", msg, 0, mlen, 16);
    }
    else if (role == DPI_ROLE_CLIENT)
    {
      if (s == 1)
        bvals[j] = 1;
      else
        bvals[j] = rand() % 2;
      if (bvals[j] == 0)
      {
        imsg(DPI_DEBUG_INIT, "%d-th s: b: %d, k is zero key", j, bvals[j]);
        key = zkey;
        klen = blen;
      }
      else
      {
        imsg(DPI_DEBUG_INIT, "%d-th s: b: %d, k is one key", j, bvals[j]);
        key = sin->skey;
        klen = sin->slen;
      }
      change_input(circuit, 1, key, klen);
      iprint(DPI_DEBUG_CIRCUIT, "Added Secret AES Key", key, 0, klen, 16);
    }

    prepare_circuit_operation(circuit);
    do {
      proceed_one_depth(circuit);
      proceed_cr_and_gates(role, sock, circuit, a, b, c);
    } while (circuit->gateq->num > 0);

    tmp = 0;
    for (x=0; x<circuit->onum; x++)
      tmp += circuit->olens[x];

    sidx = circuit->wnum - tmp;
    for (x=0; x<circuit->onum; x++)
    {
      eidx = sidx + circuit->olens[x];
      tout = (uint8_t *)calloc(circuit->olens[x], sizeof(uint8_t));
      for (y=0; sidx+y<eidx; y++)
        tout[y] = get_wire_value(circuit, sidx+y);
      dprint(DPI_DEBUG_CIRCUIT, "tout", tout, 0, (blen * 8), 16);

      for (y=0; y<circuit->olens[x]; y++)
      {
        if (circuit->type == MPC_CIRCUIT_BRISTOL_AES_128)
          circuit->obits[x][circuit->olens[x] - 1 - y] = tout[y];
        else
          circuit->obits[x][y] = tout[y];
      }
      free(tout);
      sidx = eidx;
    }

    for (x=0; x<circuit->onum; x++)
    {
      tmp = circuit->olens[x] / 8;
      for (y=0; y<tmp; y++)
        circuit->obytes[x][y] = bit_to_byte(circuit->obits[x], 8, 8*y);
    }

    rp_mb[j] = (uint8_t *)calloc(blen, sizeof(uint8_t));
    // MB sends back [RP(b_{i,j} \cdot k xor w_i)]_MB xor r_i, 
    // where [RP(b_{i,j} \cdot k xor w_i)]_MB denotes MB's secret share of 
    // RP(b_{i,j} \cdot k xor w_i) obtained from previous step.
    if (role == DPI_ROLE_MIDDLEBOX)
    {
      // RP((b and k) xor w_i)_MB xor r_i
      tout = get_output_bytes(circuit, 0, &olen);
      for (i=0; i<blen; i++)
        rp_mb[j][i] = tout[i];
      imsg(DPI_DEBUG_CIRCUIT, "olen: %d, blen: %d", olen, blen);
      assert(olen == blen);
      iprint(DPI_DEBUG_CIRCUIT, "RP(w)", (rp_mb[j]), 0, blen, 16);
      assert((min->rlen) == blen);
      for (i=0; i<blen; i++)
        buf[i] = rp_mb[j][i] ^ (min->random)[i];
      iprint(DPI_DEBUG_CIRCUIT, "RP(w) xor r", buf, 0, blen, 16);

      tbs = blen;
      offset = 0;
      while (offset < tbs)
      {
        sent = write(sock, buf+offset, blen-offset);
        offset += sent;
      }
    }
    else if (role == DPI_ROLE_CLIENT)
    {
      tbr = blen;
      offset = 0;
      while (offset < tbr)
      {
        rcvd = read(sock, rp_mb[j]+offset, blen-offset); // RP((b and k) xor w_i)_MB xor r_i
        offset += rcvd;
      }
      iprint(DPI_DEBUG_CIRCUIT, "RP(w) xor r", (rp_mb[j]), 0, blen, 16);

      rps[j] = (uint8_t *)calloc(blen, sizeof(uint8_t));
      rp_s[j] = get_output_bytes(circuit, 0, &olen); // RP(k xor w_i)_S
      assert(olen == blen);
      iprint(DPI_DEBUG_CIRCUIT, "RP(k)", (rp_s[j]), 0, blen, 16);
      for (i=0; i<blen; i++)
        rps[j][i] = rp_mb[j][i] ^ rp_s[j][i];
      iprint(DPI_DEBUG_CIRCUIT, "RP(k xor w) xor r", (rps[j]), 0, blen, 16);
      // For every b = 0, S learns RP(w_i) xor r_i, which is verified against the cert_i,
      // published by RG (if they are not equal, S aborts immediately, reporting the cheating MB
      if (bvals[j] == 0)
      {
        imsg(DPI_DEBUG_INIT, "Received rp_mb should be identical to certificate");
        verified = verify(rp_mb[j], sin->cert, blen);
      }
      // For every b = 1, S learns RP(k xor w_i) xor r_i, S verifies that this value is 
      // the same across all iterations with j \in \{j |b_{i,j}=1\} 
      // (otherwise, S aborts, reporting that MB was cheating)
      else if (bvals[j] == 1)
      {
        imsg(DPI_DEBUG_INIT, "Received rp_mb can be used to generate rp");
        verified = TRUE;
        for (i=0; i<j; i++)
        {
          if (bvals[i] == 1)
          {
            verified = verify(rps[i], rps[j], blen);
            if (verified == FALSE)
              break;
          }
        }
      }

      if (verified == TRUE)
      {
        imsg(DPI_DEBUG_INIT, "Verification success! MB is not cheating");
      }
      else
      {
        imsg(DPI_DEBUG_INIT, "Verification failure! MB is cheating!");
      }
    }
  }

  // S chooses any j such that b_{i,j} = 1 and sends (j, [RP(k xor w_i)]_S xor k) to MB
  // (here [RP(k xor w_i)]_S denotes S's share of RP(k xor w_i)),
  // so that MB can recover handle = RP(k xor w_i) xor k
  if (role == DPI_ROLE_MIDDLEBOX)
  {
    tbr = 1;
    offset = 0;
    while (offset < tbr)
    {
      rcvd = read(sock, btmp+offset, 1-offset);
      offset += rcvd;
    }
    assert(offset == tbr);
    p = btmp;
    j = *(p++);

    tbr = blen;
    offset = 0;
    while (offset < tbr)
    {
      rcvd = read(sock, btmp+offset, blen-offset);
      offset += rcvd;
    }
    assert(offset == tbr);
    iprint(DPI_DEBUG_CIRCUIT, "RP(k) xor k", btmp, 0, tbr, 16);

    for (i=0; i<blen; i++)
      hval[i] = rp_mb[j][i] ^ btmp[i];

    iprint(DPI_DEBUG_INIT, "Handle", hval, 0, blen, blen);
  }
  else if (role == DPI_ROLE_CLIENT)
  {
    chosen = FALSE;

    while (chosen == FALSE)
    {
      j = rand() % s;
      if (bvals[j] == 1)
      {
        idx = (uint8_t)j;
        tbs = 1;
        offset = 0;
        while (offset < tbs)
        {
          sent = write(sock, &idx, 1);
          offset += sent;
        }

        for (i=0; i<blen; i++)
          buf[i] = rp_s[j][i] ^ key[i];
        iprint(DPI_DEBUG_CIRCUIT, "Secret key", key, 0, blen, 16);
        iprint(DPI_DEBUG_CIRCUIT, "RP(k) xor k", buf, 0, blen, 16);

        tbs = blen;
        offset = 0;
        while (offset < tbs)
        {
          sent = write(sock, buf, blen);
          offset += sent;
        }
        chosen = TRUE;
      }
    }
  }

  for (i=0; i<SECURITY_PARAMETER; i++)
  {
    if (rp_mb[i])
      free(rp_mb[i]);

    if (rp_s[i])
      free(rp_s[i]);

    if (rps[i])
      free(rps[i]);
  }

  ffinish("ret: %d", ret);
  return ret;
}
