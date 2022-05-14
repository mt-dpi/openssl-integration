ARCH ?= X86_64

CC=$(CROSS_COMPILE)gcc
AR=$(CROSS_COMPILE)ar
LD=$(CROSS_COMPILE)ld
RM=$(CROSS_COMPILE)rm
DEBUG_LEVEL ?= 2
SHARED ?= 0

ROOT_DIRECTORY=$(PWD)/..
BIN=test_http_client test_http_server test_mb server13 client13 splittls_mb

CLIENT_SRC=test_http_client.c
CLIENT_OBJ=$(CLIENT_SRC:.c=.o)
SERVER_SRC=test_http_server.c
SERVER_OBJ=$(SERVER_SRC:.c=.o)
MB_SRC=test_mb.c
MB_OBJ=$(MB_SRC:.c=.o)
SPLITTLS_MB_SRC=splittls_mb.c
SPLITTLS_MB_OBJ=$(SPLITTLS_MB_SRC:.c=.o)
CLIENT13_SRC=client13.c
CLIENT13_OBJ=$(CLIENT13_SRC:.c=.o)
SERVER13_SRC=server13.c
SERVER13_OBJ=$(SERVER13_SRC:.c=.o)

CFLAGS=-Wall -I. -I$(ROOT_DIRECTORY)/include -DDEBUG_LEVEL=$(DEBUG_LEVEL)
LDFLAGS=-L$(ROOT_DIRECTORY)/lib -lssl -lcrypto -lsimple_http -ldpi -L. -lpthread

all: test_http_client test_http_server test_mb server13 client13 splittls_mb

test_http_client: $(CLIENT_OBJ) $(OBJS)
	$(CC) -o $@ $(CLIENT_OBJ) $(OBJS) $(LDFLAGS)
	@echo "LINK => $@"

test_http_server: $(SERVER_OBJ) $(OBJS)
	$(CC) -o $@ $(SERVER_OBJ) $(OBJS) $(LDFLAGS)
	@echo "LINK => $@"

test_mb: $(MB_OBJ) $(OBJS)
	$(CC) -o $@ $(MB_OBJ) $(OBJS) $(LDFLAGS)
	@echo "LINK => $@"

splittls_mb: $(SPLITTLS_MB_OBJ) $(OBJS)
	$(CC) -o $@ $(SPLITTLS_MB_OBJ) $(OBJS) $(LDFLAGS)
	@echo "LINK => $@"

client13: $(CLIENT13_OBJ) $(OBJS)
	$(CC) -o $@ $(CLIENT13_OBJ) $(OBJS) $(LDFLAGS)
	@echo "LINK => $@"

server13: $(SERVER13_OBJ) $(OBJS)
	$(CC) -o $@ $(SERVER13_OBJ) $(OBJS) $(LDFLAGS)
	@echo "LINK => $@"

%.o: %.c
	$(CC) -c $< $(CFLAGS)
	@echo "CC <= $<"

clean:
	$(RM) $(BIN) $(OBJS) $(CLIENT_OBJ) $(SERVER_OBJ) $(MB_OBJ) $(LIB) $(CLIENT13_OBJ) $(SERVER13_OBJ)
