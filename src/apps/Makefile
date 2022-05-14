include ../buildenv.mk

SRCS=exp_local.c exp_local_once.c exp_entries.c exp_te_internal.c exp_td_internal.c exp_td.c exp_tu_internal.c exp_up.c exp_th.c exp_te.c cache_global.c cache_perkeyword.c handle_generate.c
OBJS=$(SRCS:.c=.o)
BIN=exp_local exp_local_once exp_entries exp_te_internal exp_td_internal exp_td exp_tu_internal exp_up exp_th exp_te cache_global cache_perkeyword handle_generate


CFLAGS=$(COMMON_CFLAGS)
ifeq ($(TEST), 1)
	CFLAGS+=-DTEST
endif

all: exp_local exp_local_once exp_entries exp_te_internal exp_td_internal exp_td exp_tu_internal exp_up exp_th exp_te cache_global cache_perkeyword handle_generate

exp_local: exp_local.o
	$(CC) -o $@ $< $(COMMON_LDFLAGS)
	@echo "LD <= $<"

exp_local_once: exp_local_once.o
	$(CC) -o $@ $< $(COMMON_LDFLAGS)
	@echo "LD <= $<"

exp_entries: exp_entries.o
	$(CC) -o $@ $< $(COMMON_LDFLAGS)
	@echo "LD <= $<"

exp_te_internal: exp_te_internal.o
	$(CC) -o $@ $< $(COMMON_LDFLAGS)
	@echo "LD <= $<"

exp_td_internal: exp_td_internal.o
	$(CC) -o $@ $< $(COMMON_LDFLAGS)
	@echo "LD <= $<"

exp_tu_internal: exp_tu_internal.o
	$(CC) -o $@ $< $(COMMON_LDFLAGS)
	@echo "LD <= $<"

exp_td: exp_td.o
	$(CC) -o $@ $< $(COMMON_LDFLAGS)
	@echo "LD <= $<"

exp_up: exp_up.o
	$(CC) -o $@ $< $(COMMON_LDFLAGS)
	@echo "LD <= $<"

exp_th: exp_th.o
	$(CC) -o $@ $< $(COMMON_LDFLAGS)
	@echo "LD <= $<"

exp_te: exp_te.o
	$(CC) -o $@ $< $(COMMON_LDFLAGS)
	@echo "LD <= $<"

cache_global: cache_global.o
	$(CC) -o $@ $< $(COMMON_LDFLAGS)
	@echo "LD <= $<"

cache_perkeyword: cache_perkeyword.o
	$(CC) -o $@ $< $(COMMON_LDFLAGS)
	@echo "LD <= $<"

handle_generate: handle_generate.o
	$(CC) -o $@ $< $(COMMON_LDFLAGS)
	@echo "LD <= $<"

%.o: %.c
	$(CC) -c $< $(CFLAGS) 
	@echo "CC <= $<"

clean:
	$(RM) $(OBJS) $(BIN)
