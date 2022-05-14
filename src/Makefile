include buildenv.mk

SHARED ?= 0

LIB=libdpi.a
SHLIB=libdpi.so
VERSION=1.0.0

ROOT_DIRECTORY=$(PWD)..
UTIL_DIRECTORY=$(PWD)util
ETC_DIRECTORY=$(PWD)etc
RULE_PREPARER_DIRECTORY=$(PWD)rule_preparer
TOKENIZER_DIRECTORY=$(PWD)tokenizer
TOKEN_ENCRYPTOR_DIRECTORY=$(PWD)token_encryptor
TOKEN_DETECTOR_DIRECTORY=$(PWD)token_detector
TREE_UPDATER_DIRECTORY=$(PWD)tree_updater

SRCS=$(wildcard $(PWD)*.c)
OBJS=$(SRCS:.c=.o) 
SCHEME_OBJS=$(wildcard */*.o)

ARFLAGS=rscv
CFLAGS=$(COMMON_CFLAGS) -include $(ROOT_DIRECTORY)/src/util/dpi_names.h -include $(ROOT_DIRECTORY)/src/util/dpi_logger.h -include $(ROOT_DIRECTORY)/src/util/dpi_flags.h

ifeq ($(SHARED), 1)
	CFLAGS += -fPIC
endif

all: objs lib test apps

objs:
	make -C util
	make -C etc
	make -C rule_preparer
	make -C tokenizer
	make -C token_encryptor
	make -C token_detector
	make -C tree_updater

lib: $(OBJS)
	@echo "OBJS <= $(OBJS) $(SCHEME_OBJS)"
	$(AR) $(ARFLAGS) $(LIB) $(OBJS) $(SCHEME_OBJS)
	cp $(LIB) ../lib

apps: lib
	make -C apps

test: lib
	make -C tests

shared: $(OBJS)
	$(CC) -shared -Wl,-soname,$(SHLIB) -o $(SHLIB).$(VERSION) $(OBJS)

$(OBJS): %.o: %.c
	$(CC) $(CFLAGS) -c $<
	@echo "CC <= $<"

clean:
	make -C util clean
	make -C etc clean
	make -C tests clean
	make -C apps clean
	make -C rule_preparer clean
	make -C tokenizer clean
	make -C token_encryptor clean
	make -C token_detector clean
	make -C tree_updater clean
	$(RM) $(OBJS) $(LIB)
