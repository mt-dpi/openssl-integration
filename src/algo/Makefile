include ../buildenv.mk

SRCS=aes.c aes_test.c aes_ni.c
OBJS=$(SRCS:.c=.o)
BIN=aes_test aes_ni

CFLAGS=-march=native -Wall -I. -I$(ROOT_DIRECTORY)/include -DDEBUG_LEVEL=$(DEBUG_LEVEL) -DNDEBUG -DDEBUG_LEVEL=2 -g -O0 -msse2 -msse -maes
LDFLAGS=-L$(ROOT_DIRECTORY)/lib -L$(ROOT_DIRECTORY)/src -ldpi -lssl -lcrypto -lpthread -msse

all: aes_test aes_ni

aes_test: aes_test.o aes.o
	$(CC) -o $@ $? $(LDFLAGS)
	@echo "LD <= $<"

aes_ni: aes_ni.o
	$(CC) -o $@ $? $(LDFLAGS)
	@echo "LD <= $<"

%.o: %.c
	$(CC) -c $< $(CFLAGS) 
	@echo "CC <= $<"

clean:
	$(RM) $(OBJS) $(BIN)
