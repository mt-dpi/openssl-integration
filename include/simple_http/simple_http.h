#ifndef __SIMPLE_HTTP_H__
#define __SIMPLE_HTTP_H__

#include <inttypes.h>
#include <string.h>
#include "http_status.h"
#include "buf.h"

#define BUF_LEN               256
#define BUF_SIZE              16384
#define INDEX_FILE            "/index.html"
#define INDEX_FILE_LEN        12

#define CRLF                  "\r\n"
#define CRLF_LEN              2
#define IS_CRLF(p)            (p[0] == '\r' && p[1] == '\n')
#define ADD_CRLF(buf)         add_buf_char(buf, '\r'); add_buf_char(buf, '\n');
#define ADD_COLON(buf)        add_buf_char(buf, ':'); add_buf_char(buf, ' ');

#define DOMAIN_DELIMITER      "\n\n"
#define DOMAIN_DELIMITER_LEN  2

#define HTTP_SUCCESS          1
#define HTTP_NOT_FINISHED     0
#define HTTP_FAILURE          -1

#define HTTP_VERSION_NONE     0
#define HTTP_VERSION_1_0      1
#define HTTP_VERSION_1_1      2
#define HTTP_VERSION_2        3

#define HTTP_METHOD_NONE      0
#define HTTP_METHOD_GET       1
#define HTTP_METHOD_POST      2
#define HTTP_METHOD_PUT       4
#define HTTP_METHOD_DELETE    8

#define HTTP_TYPE_REQUEST     0
#define HTTP_TYPE_RESPONSE    1

#define HTTP_RESOURCE_MEM     0
#define HTTP_RESOURCE_FILE    1

typedef struct attribute_st {
  char *key;
  int klen;
  char *value;
  int vlen;
  struct attribute_st *next;
} attribute_t;

typedef struct resource_st {
  int type;
  int size;
  int offset;
  void *ptr;
} resource_t;

typedef struct http_st {
  int type;
  int version;
  int method;
  int code;
  int header;
  int body;
  int chunked;

  char *host;
  int hlen;
  char *abs_path;
  int alen;

  int num_of_attr;
  attribute_t *hdr;
  
  resource_t *resource;
} http_t;

void init_http_module(void);

attribute_t *init_attribute(char *key, int klen, char *value, int vlen);
void free_attribute(attribute_t *attr);

http_t *init_http_message(int type);
void free_http_message(http_t *http);

void http_set_version(http_t *http, int version);
void http_set_method(http_t *http, int method);
void http_set_domain(http_t *http, const char *domain, int dlen);
void http_set_abs_path(http_t *http, const char *abs_path, int alen);
void http_set_default_attributes(http_t *http);

attribute_t *find_header_attribute(http_t *http, char *key, int klen);
int add_header_attribute(http_t *http, char *key, int klen, char *value, int vlen);
void del_header_attribute(http_t *http, char *key, int klen);
void print_header(http_t *http);

resource_t *http_init_resource(http_t *http);
resource_t *http_get_resource(http_t *http);
void http_update_resource(http_t *http, int sent);

int http_serialize(http_t *http, uint8_t *msg, int max, int *mlen);
int http_deserialize(uint8_t *buf, int len, http_t *http, FILE *fp);

int char_to_int(uint8_t *str, uint32_t slen, int base);
int int_to_char(int num, uint8_t *str, int base);


#endif /* __SIMPLE_HTTP_H__ */
