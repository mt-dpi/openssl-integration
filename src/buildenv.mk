SHELL=/bin/bash
DEBUG_LEVEL ?= 3
INTERNAL ?= 0
CC=$(CROSS_COMPILE)gcc
AR=$(CROSS_COMPILE)ar
LD=$(CROSS_COMPILE)ld
RM=$(CROSS_COMPILE)rm

PWD= $(dir $(abspath $(lastword $(MAKEFILE_LIST))))
ROOT_DIRECTORY=$(PWD)..

COMMON_CFLAGS=-Wall -I. -I$(ROOT_DIRECTORY)/include -DDEBUG_LEVEL=$(DEBUG_LEVEL) -DNDEBUG #-DCIRCUIT_DEBUG 

ifeq ($(TEST), 1)
	COMMON_CFLAGS+=-DTEST
endif

ifeq ($(INTERNAL), 1)
	COMMON_CFLAGS+=-DINTERNAL
endif

COMMON_LDFLAGS=-L$(ROOT_DIRECTORY)/lib -L$(ROOT_DIRECTORY)/src -ldpi -lssl -lcrypto -lpthread


