#include <stdlib.h>
#include <dpi/broker.h>
#include <dpi/debug.h>
#include <dpi/defines.h>

int broker_find_search_tree_token(broker_t *broker, etoken_t *etoken)
{
  fstart("broker: %p, etoken: %p", broker, etoken);
  assert(broker != NULL);
  assert(etoken != NULL);

  int ret, rc, id;
  request_t *req;
  response_t *resp;

  ret = FAILURE;
  rc = FAILURE;
  resp = NULL;
  req = init_request(BROKER_OP_SEARCH_NODE, NULL, etoken);
  while (rc == FAILURE)
    rc = add_request_to_queue(broker, req);
  id = get_request_id(req);

  while (!resp)
    resp = get_response_from_queue(broker, id);

  ret = resp->result;
  free_response(resp);

  ffinish("ret: %d", ret);
  return ret;
}

int broker_insert_search_tree_token(broker_t *broker, etoken_t *handle, etoken_t *etoken)
{
  fstart("handle: %p, etoken: %p", handle, etoken);

  int ret;
  request_t *req;

  ret = FAILURE;
  req = init_request(BROKER_OP_INSERT_NODE, handle, etoken);

  while (ret == FAILURE)
    ret = add_request_to_queue(broker, req);

  ffinish("ret: %p", ret);
  return ret;
}

int broker_delete_search_tree_token(broker_t *broker, etoken_t *etoken)
{
  fstart("broker: %p, etoken: %p", broker, etoken);
  assert(broker != NULL);
  assert(etoken != NULL);

  int ret;
  request_t *req;

  ret = FAILURE;
  req = init_request(BROKER_OP_DELETE_NODE, NULL, etoken);

  while (ret == FAILURE)
    ret = add_request_to_queue(broker, req);

  ffinish("ret: %d", ret);
  return ret;
}

int broker_active_search_tree(broker_t *broker)
{
  fstart("broker: %p", broker);
  assert(broker != NULL);

  int ret;
  request_t *req;

  ret = FAILURE;
  req = init_request(BROKER_OP_ACTIVE_TREE, NULL, NULL);

  while (ret == FAILURE)
    ret = add_request_to_queue(broker, req);

  ffinish("ret: %d", ret);
  return ret;
}

broker_t *init_broker(void)
{
  fstart();

  broker_t *ret;
  ret = (broker_t *)calloc(1, sizeof(broker_t));

  ffinish();
  return ret;
}

int add_request_to_queue(broker_t *broker, request_t *req)
{
  fstart("broker: %p, req: %p", broker, req);
  assert(broker != NULL);
  assert(req != NULL);
  
  int ret;
  int reqidx;

  ret = FAILURE;
  reqidx = broker->req_aidx;
  if (broker->req_occupied[reqidx])
    goto out;
  broker->req[reqidx] = req;
  broker->req_occupied[reqidx] = 1;
  reqidx = (reqidx + 1) % MAX_SLOTS;
  broker->req_aidx = reqidx;
  ret = SUCCESS;

out:
  ffinish("ret: %d", ret);
  return ret;
}

int add_response_to_queue(broker_t *broker, response_t *resp)
{
  fstart("broker: %p, req: %p", broker, resp);
  assert(broker != NULL);
  assert(resp != NULL);
  
  int ret;
  int respidx;

  ret = FAILURE;
  respidx = broker->resp_aidx;
  if (broker->resp_occupied[respidx])
    goto out;
  broker->resp[respidx] = resp;
  broker->resp_occupied[respidx] = 1;
  respidx = (respidx + 1) % MAX_SLOTS;
  broker->resp_aidx = respidx;
  ret = SUCCESS;

out:
  ffinish("ret: %d", ret);
  return ret;
}

request_t *get_request_from_queue(broker_t *broker)
{
  fstart("broker: %p", broker);
  assert(broker != NULL);

  request_t *ret;
  int reqidx;

  ret = NULL;
  reqidx = broker->req_gidx;
  if (!broker->req_occupied[reqidx])
    goto out;
  ret = broker->req[reqidx];
  broker->req_occupied[reqidx] = 0;
  reqidx = (reqidx + 1) % MAX_SLOTS;
  broker->req_gidx = reqidx;

out:
  ffinish("ret: %p", ret);
  return ret;
}

response_t *get_response_from_queue(broker_t *broker, int id)
{
  fstart("broker: %p, id: %d", broker, id);
  assert(broker != NULL);
  assert(id >= 0);

  response_t *ret;
  int i;

  ret = NULL;

  for (i=0; i<MAX_SLOTS; i++)
  {
    if (broker->resp_occupied[i] == 1 && broker->resp[i]->id == id)
    {
      ret = broker->resp[i];
      broker->resp_occupied[i] = 0;
      break;
    }
  }

  ffinish("ret: %p", ret);
  return ret;
}

request_t *init_request(int op, etoken_t *handle, etoken_t *etoken)
{
  fstart("op: %d, handle: %p, etoken: %p", op, handle, etoken);
  assert(etoken != NULL);

  request_t *ret;
  ret = (request_t *)calloc(1, sizeof(request_t));
  ret->id = rand();
  ret->op = op;
  ret->handle = handle;
  ret->etoken = etoken;

  ffinish("ret: %p", ret);
  return ret;
}

int get_request_id(request_t *req)
{
  fstart("req: %p", req);
  assert(req != NULL);

  int ret;
  ret = req->id;

  ffinish("ret: %d", ret);
  return ret;
}

void free_request(request_t *req)
{
  fstart("req: %p", req);

  if (req)
  {
    free(req);
  }

  ffinish();
}

response_t *init_response(int id, int result)
{
  fstart("id: %d, result: %d", id, result);

  response_t *ret;
  ret = (response_t *)calloc(1, sizeof(response_t));
  ret->id = id;
  ret->result = result;

  ffinish("ret: %p", ret);
  return ret;
}

void free_response(response_t *resp)
{
  fstart("resp: %p", resp);

  if (resp)
    free(resp);

  ffinish();
}

