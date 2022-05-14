include ../buildenv.mk

SRCS=$(wildcard *.c)
OBJS=$(SRCS:.c=.o)

all: $(OBJS)

%.o: %.c
	$(CC) -c $< $(COMMON_CFLAGS)
	@echo "CC <= $<"

clean:
	$(RM) $(OBJS) 
