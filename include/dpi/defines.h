#ifndef __DEFINES_H__
#define __DEFINES_H__

#define TRUE 1
#define FALSE 0

#define SUCCESS 1
#define FAILURE -1

#define INVALID 0
#define BUF_SIZE 16384

#define PTR_TO_VAR_2BYTES(p, v) \
  v = (((p[0] & 0xff) << 8) | (p[1] & 0xff)); p += 2;
#define VAR_TO_PTR_2BYTES(v, p) \
  p[0] = (v >> 8) & 0xff; p[1] = (v & 0xff); p += 2;

#define PTR_TO_VAR_3BYTES(p, v) \
  v = (((p[0] & 0xff) << 16) | ((p[1] & 0xff) << 8) | (p[2] & 0xff)); p += 3;
#define VAR_TO_PTR_3BYTES(v, p) \
  p[0] = (v >> 16) & 0xff; p[1] = (v >> 8) & 0xff; p[2] = (v & 0xff); p += 3;


#define PTR_TO_VAR_4BYTES(p, v) \
  v = (((p[0] & 0xff) << 24) | ((p[1] & 0xff) << 16) | ((p[2] & 0xff) << 8) | (p[3] & 0xff)); \
      p += 4;
#define VAR_TO_PTR_4BYTES(v, p) \
  p[0] = (v >> 24) & 0xff; p[1] = (v >> 16) & 0xff; p[2] = (v >> 8) & 0xff; p[3] = v & 0xff; \
      p += 4;

#endif /* __DEFINES_H__ */
