include ../buildenv.mk

CC=gcc
SRCS=init_test.c tokenizer_test.c token_encryptor_test.c token_detector_test.c circuit_test.c base64_test.c fernet_test.c gc_garbler_test.c gc_evaluator_test.c ot_garbler_test.c ot_evaluator_test.c cr_sender_test.c cr_mb_test.c cr_sender_single_test.c cr_mb_single_test.c search_tree_test.c
OBJS=$(SRCS:.c=.o)
BIN=init_test tokenizer_test token_encryptor_test token_detector_test circuit_test base64_test fernet_test gc_garbler_test gc_evaluator_test ot_garbler_test ot_evaluator_test cr_sender_test cr_mb_test cr_sender_single_test cr_mb_single_test search_tree_test

CFLAGS=$(COMMON_CFLAGS)
ifeq ($(TEST), 1)
	CFLAGS+=-DTEST
endif

all: init_test tokenizer_test token_encryptor_test token_detector_test circuit_test base64_test fernet_test gc_garbler_test gc_evaluator_test ot_garbler_test ot_evaluator_test cr_sender_test cr_mb_test cr_sender_single_test cr_mb_single_test search_tree_test

init_test: init_test.o
	$(CC) -o $@ $< $(COMMON_LDFLAGS)
	@echo "LD <= $<"

tokenizer_test: tokenizer_test.o
	$(CC) -o $@ $< $(COMMON_LDFLAGS)
	@echo "LD <= $<"

token_encryptor_test: token_encryptor_test.o
	$(CC) -o $@ $< $(COMMON_LDFLAGS)
	@echo "LD <= $<"

token_detector_test: token_detector_test.o
	$(CC) -o $@ $< $(COMMON_LDFLAGS)
	@echo "LD <= $<"

circuit_test: circuit_test.o
	$(CC) -o $@ $< $(COMMON_LDFLAGS)
	@echo "LD <= $<"

base64_test: base64_test.o
	$(CC) -o $@ $< $(COMMON_LDFLAGS)
	@echo "LD <= $<"

fernet_test: fernet_test.o
	$(CC) -o $@ $< $(COMMON_LDFLAGS)
	@echo "LD <= $<"

gc_garbler_test: gc_garbler_test.o
	$(CC) -o $@ $< $(COMMON_LDFLAGS)
	@echo "LD <= $<"

gc_evaluator_test: gc_evaluator_test.o
	$(CC) -o $@ $< $(COMMON_LDFLAGS)
	@echo "LD <= $<"

ot_garbler_test: ot_garbler_test.o
	$(CC) -o $@ $< $(COMMON_LDFLAGS)
	@echo "LD <= $<"

ot_evaluator_test: ot_evaluator_test.o
	$(CC) -o $@ $< $(COMMON_LDFLAGS)
	@echo "LD <= $<"

cr_sender_test: cr_sender_test.o
	$(CC) -o $@ $< $(COMMON_LDFLAGS)
	@echo "LD <= $<"

cr_mb_test: cr_mb_test.o
	$(CC) -o $@ $< $(COMMON_LDFLAGS)
	@echo "LD <= $<"

cr_sender_single_test: cr_sender_single_test.o
	$(CC) -o $@ $< $(COMMON_LDFLAGS)
	@echo "LD <= $<"

cr_mb_single_test: cr_mb_single_test.o
	$(CC) -o $@ $< $(COMMON_LDFLAGS)
	@echo "LD <= $<"

search_tree_test: search_tree_test.o
	$(CC) -o $@ $< $(COMMON_LDFLAGS)
	@echo "LD <= $<"

%.o: %.c
	$(CC) -c $< $(CFLAGS) 
	@echo "CC <= $<"

clean:
	$(RM) $(OBJS) $(BIN)
