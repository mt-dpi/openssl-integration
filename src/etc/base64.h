#ifndef __BASE64_H__
#define __BASE64_H__

#include <stdint.h>

// output buffers should be allocated
int base64_url_encode(uint8_t *in, int ilen, uint8_t *out, int *olen);
int base64_url_decode(uint8_t *in, int ilen, uint8_t *out, int *olen);

#endif /* __BASE64_H__ */
