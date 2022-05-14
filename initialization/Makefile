CC=gcc
BIN=mb sender preprocessing
OBJS=mb.o sender.o circuit.o preprocessing.o
DEBUG_LEVEL=2
CFLAGS=-I../include -DDEBUG_LEVEL=$(DEBUG_LEVEL)
LDFLAGS=-L../lib -lssl -lcrypto -lpthread

all: mb sender preprocessing

mb: mb.o circuit.o
	$(CC) -o $@ $^ $(LDFLAGS)

sender: sender.o circuit.o
	$(CC) -o $@ $^ $(LDFLAGS)

preprocessing: preprocessing.o
	$(CC) -o $@ $< $(LDFLAGS)

$(OBJS): %.o: %.c
	$(CC) $(CFLAGS) -c $<
	@echo "CC <= $<"

clean:
	$(RM) $(OBJS) $(BIN)
