CC=gcc
LD=gcc
RM=rm
SRCS=$(wildcard *.c)
OBJS=$(SRCS:.c=.o)
BIN=evp_variant1 evp_variant2 evp_variant3 evp_variant4 evp_variant5
CFLAGS=-I../include
LDFLAGS=-L../lib -lcrypto

all: evp_variant1 evp_variant2 evp_variant3 evp_variant4 evp_variant5

evp_variant1: evp_variant1.o
	$(LD) -o $@ $< $(LDFLAGS)
	@echo "LD <= $<"

evp_variant2: evp_variant2.o
	$(LD) -o $@ $< $(LDFLAGS)
	@echo "LD <= $<"

evp_variant3: evp_variant3.o
	$(LD) -o $@ $< $(LDFLAGS)
	@echo "LD <= $<"

evp_variant4: evp_variant4.o
	$(LD) -o $@ $< $(LDFLAGS)
	@echo "LD <= $<"

evp_variant5: evp_variant5.o
	$(LD) -o $@ $< $(LDFLAGS)
	@echo "LD <= $<"

$(OBJS): %.o: %.c
	$(CC) $(CFLAGS) -c $<
	@echo "CC <= $<"

clean:
	$(RM) $(OBJS) $(BIN)
	@echo "RM <= $(OBJS) $(BIN)"
