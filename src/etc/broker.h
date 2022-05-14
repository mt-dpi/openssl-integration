#ifndef __BROKER_H__
#define __BROKER_H__

#define BROKER_OP_INSERT_NODE 1
#define BROKER_OP_DELETE_NODE 2
#define BROKER_OP_SEARCH_NODE 3
#define BROKER_OP_ACTIVE_TREE 4

#include <dpi/dpi_types.h>
#include <dpi/setting.h>
#include <stdint.h>

struct broker_st {
  int req_aidx;
  int req_gidx;
  request_t *req[MAX_SLOTS];
  uint8_t req_occupied[MAX_SLOTS];
  
  int resp_aidx;
  response_t *resp[MAX_SLOTS];
  uint8_t resp_occupied[MAX_SLOTS];
};

struct request_st {
  int id;
  int op;
  etoken_t *handle;
  etoken_t *etoken;
};

struct response_st {
  int id;
  int result;
};

broker_t *init_broker(void);
int add_request_to_queue(broker_t *broker, request_t *req);
int add_response_to_queue(broker_t *broker, response_t *resp);
request_t *get_request_from_queue(broker_t *broker);
response_t *get_response_from_queue(broker_t *broker, int id);

request_t *init_request(int op, etoken_t *handle, etoken_t *etoken);
int get_request_id(request_t *req);
void free_request(request_t *req);

response_t *init_response(int id, int result);
void free_response(response_t *resp);

int broker_find_search_tree_token(broker_t *broker, etoken_t *etoken);
int broker_insert_search_tree_token(broker_t *broker, etoken_t *handle, etoken_t *etoken);
int broker_delete_search_tree_token(broker_t *broker, etoken_t *etoken);
int broker_active_search_tree(broker_t *broker);
#endif /* __BROKER_H__ */
