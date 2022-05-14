#ifndef __PBYTES_H__
#define __PBYTES_H__

#define VAR_TO_PTR_8BYTES(v, p) \
  p[0] = (v >> 56) & 0xff; p[1] = (v >> 48) & 0xff; p[2] = (v >> 40) & 0xff; \
  p[3] = (v >> 32) & 0xff; p[4] = (v >> 24) & 0xff; p[5] = (v >> 16) & 0xff; \
  p[6] = (v >> 8) & 0xff; p[7] = v & 0xff;

#define PTR_TO_VAR_8BYTES(p, v) \
  v = 0; v |= ((p[0] & 0xff) << 56); v |= ((p[1] & 0xff) << 48); \
  v |= ((p[2] & 0xff) << 40); v |= ((p[3] & 0xff) << 32); \
  v |= ((p[4] & 0xff) << 24); v |= ((p[5] & 0xff) << 16); \
  v |= ((p[6] & 0xff) << 8); v |= (p[7] & 0xff);

#endif /* __PBYTES_H__ */
