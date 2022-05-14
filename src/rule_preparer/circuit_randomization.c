#include <unistd.h>
#include <dpi/dpi.h>
#include <dpi/debug.h>
#include <dpi/defines.h>
#include <dpi/circuit_randomization.h>
#include <openssl/ssl.h>
#include "rule_preparer.h"
#include "../etc/security_context.h"

int circuit_randomization_rule_preparation(dpi_t *dpi)
{
	fstart("dpi: %p", dpi);
	assert(dpi != NULL);

	int i, ret, sock, nrules, sent, rcvd, offset, tbs, tbr, role;
  mb_input_t *min;
  sender_input_t *sin;
  security_context_t *ctx;
  uint8_t **certs;
  uint8_t *p;
  uint8_t buf[BUF_SIZE];
  SSL *ssl;

	ret = FAILURE;
  min = NULL;
  sin = NULL;
  ssl = dpi_get_ssl_session(dpi);;
  sock = SSL_get_fd(ssl);
  ctx = dpi_get_security_context(dpi);
  role = dpi_get_role(dpi);

  if (role == DPI_ROLE_MIDDLEBOX)
  {
    certs = SSL_mt_dpi_get_certificates(ssl, &nrules);
    min = (mb_input_t *)calloc(1, sizeof(mb_input_t));
    min->pkey = get_context_encryption_key(ctx, &(min->plen));
    min->random = get_context_rgrand(ctx, &(min->rlen));
    
    p = buf;
    VAR_TO_PTR_4BYTES(nrules, p);
    tbs = (p-buf);
    offset = 0;
    while (offset < tbs)
    {
      sent = write(sock, buf+offset, tbs-offset);
      offset += sent;
    }
    assert(offset == tbs);

    for (i=0; i<nrules; i++)
    {
      tbs = 16;
      offset = 0;
      while (offset < tbs)
      {
        sent = write(sock, certs[i]+offset, tbs-offset);
        offset += sent;
      }
      assert(offset == tbs);
    }
    circuit_randomization(role, sock, 0, 0, 0, min);
  }
  else if (role == DPI_ROLE_CLIENT)
  {                                                                 
    tbr = 4;
    offset = 0;
    while (offset < tbr)
    {
      rcvd = read(sock, buf+offset, tbr-offset);
      offset += rcvd;
    }
    assert(offset == rcvd);

    p = buf;
    PTR_TO_VAR_4BYTES(p, nrules);

    certs = (uint8_t **)calloc(nrules, sizeof(uint8_t *));
    for (i=0; i<nrules; i++)
    {
      certs[i] = (uint8_t *)calloc(16, sizeof(uint8_t));
      tbr = 16;
      offset = 0;
      while (offset < tbr)
      {
        rcvd = read(sock, certs[i]+offset, tbr-offset);
        offset += rcvd;
      }
      assert(offset == tbr);
    }
    dpi_set_cr_certificates(dpi, certs, nrules);

    sin = (sender_input_t *)calloc(1, sizeof(sender_input_t));
    sin->pkey = get_context_encryption_key(ctx, &(sin->plen));
    sin->skey = get_context_secret(ctx, &(sin->slen));
    circuit_randomization(role, sock, 0, 0, 0, sin);
  }
  else
  {
    emsg("This should not be happened");
  }

	ffinish("ret: %d", ret);
	return ret;
}
