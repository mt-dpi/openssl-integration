#include <dpi.h>
#include <debug.h>
#include <defines.h>
#include <stdint.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <openssl/evp.h>
#include <time.h>
#include <sys/time.h>

#include "aes_expanded.h"
#include "circuit.h"
#include "hardcode.h"
#include "../src/test_values.h"

#define OUTPUT_IDX 29100
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

uint8_t bit_to_byte(uint8_t *a, int addr)
{
  uint8_t ret;
  int i, last;
  ret = 0;

  for (i=0; i<8; i++)
    ret = ret * 2 + a[i+addr];

  return ret;
}

uint8_t *byte_to_bit(uint8_t *b, int len)
{
  uint8_t *ret;
  int i, j, val;
  ret = (uint8_t *)malloc(8 * len);

  for (i=0; i<len; i++)
  {
    val = b[i];
    for (j=0; j<8; j++)
    {
      ret[8*(i+1)-j-1] = val % 2;
      val = val / 2;
    }
  }

  return ret;
}

uint8_t xor(uint8_t a, uint8_t b)
{
  assert(a == 0 || a == 1);
  assert(b == 0 || b == 1);
  return a == b? 0 : 1;
}

uint8_t and(uint8_t a, uint8_t b)
{
  assert(a == 0 || a == 1);
  assert(b == 0 || b == 1);
  return a * b;
}

uint8_t inv(uint8_t a)
{
  assert(a == 0 || a == 1);
  return a == 1? 0 : 1;
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

  ffinish("ret: %d", ret);
  return ret;
}

int circuit_randomization(int role, int sock, int circuit, uint8_t a, uint8_t b, uint8_t c, 
    uint8_t *cert, int clen, uint8_t *random, int rlen, uint8_t *keyword, int klen)
{
  fstart("role: %d, sock: %d, circuit: %d, a: %d, b: %d, c: %d, cert: %p, clen: %d, random: %p, rlen: %d, keyword: %s, klen", role, sock, circuit, a, b, c, keyword, klen);
  assert(sock > 0);
  assert(circuit >= 0);

  int i, j, ret, num_wire, num_gate, num_input, blk_size, key_size, gate, nline, bsize, nand;
  int sent, rcvd;
  int in1_idx, in2_idx, out_idx;
  uint8_t *wire, *pkey, *kxw, *k, *w, *wtmp, *key;
  uint8_t x, y, z, s, idx;
  uint8_t xa, yb, tmp;
  const uint32_t *rows;
  uint8_t sbuf[2] = {0, };
  uint8_t rbuf[2] = {0, };
  uint8_t tbs[16] = {0, };
  uint8_t hval[16] = {0, };
  uint8_t skey[16] = {1, };
  uint8_t zkey[16] = {0, };
  uint8_t bvals[SECURITY_PARAMETER] = {0, };
  uint8_t *rp_mb[SECURITY_PARAMETER] = {NULL, };
  uint8_t *rp_s[SECURITY_PARAMETER] = {NULL, };
  uint8_t *rps[SECURITY_PARAMETER] = {NULL, };
  uint8_t buf[16] = {0, };
  int verified, chosen;

  ret = SUCCESS;
  s = SECURITY_PARAMETER;
  srand(time(NULL));
  nand = 0;

  switch (circuit)
  {
    case CIRCUIT_TYPE_AES:
      num_wire = aes_num_wire;
      num_gate = aes_num_gate;
      key_size = aes_key_size;
      blk_size = 128;
      bsize = 16;
      num_input = blk_size + key_size;
      rows = aes_rows;
      break;

    default:
      num_wire = aes_num_wire;
      num_gate = aes_num_gate;
      key_size = aes_key_size;
      blk_size = 128;
      bsize = 16;
      num_input = blk_size + key_size;
      rows = aes_rows;
  }

  if (keyword)
  {
    iprint(DPI_DEBUG_INIT, "Keyword", keyword, 0, klen, klen);
    iprint(DPI_DEBUG_INIT, "Random", random, 0, bsize, bsize);
    iprint(DPI_DEBUG_INIT, "Certificate", cert, 0, bsize, bsize);
  }

  if (role == DPI_ROLE_MIDDLEBOX)
  {
    dmsg(DPI_DEBUG_INIT, "Middlebox >");
  }
  else if (role == DPI_ROLE_CLIENT)
  {
    dmsg(DPI_DEBUG_INIT, "Sender >");
  }
  dmsg(DPI_DEBUG_INIT, "num_wire: %d", num_wire);
  dmsg(DPI_DEBUG_INIT, "num_gate: %d", num_gate);
  dmsg(DPI_DEBUG_INIT, "key_size: %d", key_size);
  dmsg(DPI_DEBUG_INIT, "blk_size: %d", blk_size);
  dmsg(DPI_DEBUG_INIT, "num_input: %d", num_input);
  
  if (role == DPI_ROLE_MIDDLEBOX)
  {
    dmsg(DPI_DEBUG_INIT, "a1: %d", a);
    dmsg(DPI_DEBUG_INIT, "b1: %d", b);
    dmsg(DPI_DEBUG_INIT, "c1: %d", c);
  }
  else if (role == DPI_ROLE_CLIENT)
  {
    dmsg(DPI_DEBUG_INIT, "a2: %d", a);
    dmsg(DPI_DEBUG_INIT, "b2: %d", b);
    dmsg(DPI_DEBUG_INIT, "c2: %d", c);
  }

  wire = (uint8_t *)calloc(num_wire, sizeof(uint8_t));
  pkey = (uint8_t *)aes_hardcoded_key;
  kxw = (uint8_t *)calloc(blk_size, sizeof(uint8_t));
  memcpy(wire + blk_size, pkey, key_size); // publickly known key

  if (keyword)
  {
    wtmp = byte_to_bit(keyword, klen); 
    w = (uint8_t *)calloc(blk_size, sizeof(uint8_t)); // w_i
    memcpy(w, wtmp, klen * 8);
  }

  // Repeat the folloiwng s times where s is a statistical security parameter. 
  // In the j-th repetition:
  for (j=0; j<s; j++)
  {
    if (role == DPI_ROLE_MIDDLEBOX)
    {
      key = zkey;
    }
    else if (role == DPI_ROLE_CLIENT)
    {
      bvals[j] = rand() % 2;
      if (bvals[j] == 0)
      {
        dmsg(DPI_DEBUG_INIT, "%d-th s: b: %d, k is zero key", j, bvals[j]);
        key = zkey;
      }
      else
      {
        dmsg(DPI_DEBUG_INIT, "%d-th s: b: %d, k is one key", j, bvals[j]);
        key = skey;
      }
    }

    if (keyword)
    {
      klen = strlen(keyword);
      k = byte_to_bit(key, bsize); // k

      for (i=0; i<blk_size; i++)
        kxw[i] = xor(k[i], w[i]); // k xor w_i
      memcpy(wire, kxw, blk_size); // k xor w_i
    }

    // AES
    for (i=0; i<num_gate; i++)
    {
      gate = rows[i*4];
    
      switch (gate)
      {
      case GATE_TYPE_AND:
        nand++;
        in1_idx = rows[i * 4 + 1];
        in2_idx = rows[i * 4 + 2];
        out_idx = rows[i * 4 + 3];

        x = wire[in1_idx];
        y = wire[in2_idx];

        sbuf[0] = xor(a, x);
        sbuf[1] = xor(b, y);

        if (role == DPI_ROLE_MIDDLEBOX)
        {
          sent = write(sock, sbuf, 2);
          assert(sent == 2);
          dmsg(DPI_DEBUG_INIT, "sent: %d", sent);
          rcvd = read(sock, rbuf, 2);
          assert(rcvd == 2);
          dmsg(DPI_DEBUG_INIT, "rcvd: %d", rcvd);
          dmsg(DPI_DEBUG_INIT, "Round %d (MB)> sbuf[0]: %d, sbuf[1]: %d", i, sbuf[0], sbuf[1]);
          dmsg(DPI_DEBUG_INIT, "Round %d (MB)> rbuf[0]: %d, rbuf[1]: %d", i, rbuf[0], rbuf[1]);
        }
        else if (role == DPI_ROLE_CLIENT)
        {
          rcvd = read(sock, rbuf, 2);
          assert(rcvd == 2);
          dmsg(DPI_DEBUG_INIT, "rcvd: %d", rcvd);
          sent = write(sock, sbuf, 2);
          assert(sent == 2);
          dmsg(DPI_DEBUG_INIT, "sent: %d", sent);
          dmsg(DPI_DEBUG_INIT, "Round %d (S)> sbuf[0]: %d, sbuf[1]: %d", i, sbuf[0], sbuf[1]);
          dmsg(DPI_DEBUG_INIT, "Round %d (S)> rbuf[0]: %d, rbuf[1]: %d", i, rbuf[0], rbuf[1]);
        }

        xa = xor(sbuf[0], rbuf[0]);
        yb = xor(sbuf[1], rbuf[1]);

        if (role == DPI_ROLE_MIDDLEBOX)
        {
          tmp = and(xa, yb); // xa*yb
          tmp = xor(tmp, inv(and(xa, b))); // xa*yb - xa*b
          tmp = xor(tmp, inv(and(yb, a))); // xa*yb - xa*b - yb*a
          tmp = xor(tmp, c);
          z = wire[out_idx] = tmp;
          dmsg(DPI_DEBUG_INIT, "Round %d (MB)> xa: %d, yb: %d", i, xa, yb);
          dmsg(DPI_DEBUG_INIT, "Round %d (MB)> z: %d", i, z);
        }
        else if (role == DPI_ROLE_CLIENT)
        {
          z = wire[out_idx] = (((((xa * b) + 1) % 2) + (((yb * a) + 1) % 2)) % 2 + c) % 2;
          tmp = inv(and(xa, b)); // -xa*b
          tmp = xor(tmp, inv(and(yb, a))); // -xa*b -yb*a
          tmp = xor(tmp, c); // -xa*b -yb*a + c
          dmsg(DPI_DEBUG_INIT, "Round %d (S)> xa: %d, yb: %d", i, xa, yb);
          dmsg(DPI_DEBUG_INIT, "Round %d (S)> z: %d, out_idx: %d", i, z, out_idx);
        }
        break;

      case GATE_TYPE_XOR:
        in1_idx = rows[i * 4 + 1];
        in2_idx = rows[i * 4 + 2];
        out_idx = rows[i * 4 + 3];

        wire[out_idx] = xor(wire[in1_idx], wire[in2_idx]);
        dmsg(DPI_DEBUG_INIT, "Round %d> out_idx: %d", i, out_idx);
        break;

      default:
        in1_idx = rows[i * 4 + 1];
        out_idx = rows[i * 4 + 3];

        if (role == DPI_ROLE_MIDDLEBOX)
        {
          wire[out_idx] = inv(wire[in1_idx]);
        }
        else if (role == DPI_ROLE_CLIENT)
        {
          wire[out_idx] = wire[in1_idx];
        }
        dmsg(DPI_DEBUG_INIT, "Round %d> out_idx: %d", i, out_idx);
      }
    }

    rp_mb[j] = (uint8_t *)calloc(bsize, sizeof(uint8_t));
    // MB sends back [RP(b_{i,j} \cdot k xor w_i)]_MB xor r_i, 
    // where [RP(b_{i,j} \cdot k xor w_i)]_MB denotes MB's secret share of 
    // RP(b_{i,j} \cdot k xor w_i) obtained from previous step.
    if (role == DPI_ROLE_MIDDLEBOX)
    {
      // RP((b and k) xor w_i)_MB xor r_i
      for(i=0; i<bsize; i++)
        rp_mb[j][i] = bit_to_byte(wire, 8*i+OUTPUT_IDX) ^ random[i]; 
      sent = write(sock, rp_mb[j], bsize);
    }
    else if (role == DPI_ROLE_CLIENT)
    {
      rcvd = read(sock, rp_mb[j], bsize); // RP((b and k) xor w_i)_MB xor r_i

      rp_s[j] = (uint8_t *)calloc(bsize, sizeof(uint8_t));
      rps[j] = (uint8_t *)calloc(bsize, sizeof(uint8_t));
      for (i=0; i<bsize; i++)
      {
        rp_s[j][i] = bit_to_byte(wire, 8*i+OUTPUT_IDX); // RP(k xor w_i)_S
        rps[j][i] = rp_mb[j][i] ^ rp_s[j][i];
      }
      // For every b = 0, S learns RP(w_i) xor r_i, which is verified against the cert_i,
      // published by RG (if they are not equal, S aborts immediately, reporting the cheating MB
      if (bvals[j] == 0)
      {
        dmsg(DPI_DEBUG_INIT, "Received rp_mb should be identical to certificate");
        verified = verify(rp_mb[j], cert, bsize);
      }
      // For every b = 1, S learns RP(k xor w_i) xor r_i, S verifies that this value is 
      // the same across all iterations with j \in \{j |b_{i,j}=1\} 
      // (otherwise, S aborts, reporting that MB was cheating)
      else if (bvals[j] == 1)
      {
        dmsg(DPI_DEBUG_INIT, "Received rp_mb can be used to generate rp");
        verified = TRUE;
        for (i=0; i<j; i++)
        {
          if (bvals[i] == 1)
          {
            verified = verify(rps[i], rps[j], bsize);
            if (verified == FALSE)
              break;
          }
        }
      }

      if (verified == TRUE)
      {
        dmsg(DPI_DEBUG_INIT, "Verification success! MB is not cheating");
      }
      else
      {
        dmsg(DPI_DEBUG_INIT, "Verification failure! MB is cheating!");
      }
    }
    memset(wire, 0, num_wire);
  }

  // S chooses any j such that b_{i,j} = 1 and sends (j, [RP(k xor w_i)]_S xor k) to MB
  // (here [RP(k xor w_i)]_S denotes S's share of RP(k xor w_i)),
  // so that MB can recover handle = RP(k xor w_i) xor k
  if (role == DPI_ROLE_MIDDLEBOX)
  {
    read(sock, buf, 1);
    j = buf[0];
    read(sock, buf, bsize);

    for (i=0; i<bsize; i++)
    {
      hval[i] = rp_mb[j][i] ^ buf[i];
    }

    iprint(DPI_DEBUG_INIT, "Handle", hval, 0, bsize, bsize);
    imsg(DPI_DEBUG_INIT, "# of AND gates: %d", nand);
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
        write(sock, &idx, 1);
        for (i=0; i<bsize; i++)
        {
          tbs[i] = rp_s[j][i] ^ skey[i];
        }
        write(sock, tbs, bsize);
        chosen = TRUE;
      }
    }
  }

  free(wire);

  ffinish("ret: %d", ret);
  return ret;
}
