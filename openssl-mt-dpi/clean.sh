#!/bin/bash

if test -f "Makefile"; then
  make clean
  rm Makefile
fi
find ../src -name *.o -exec rm {} \;
find ../src -name *.d -exec rm {} \;
rm ssl/dpi_local.c
rm ssl/dpi_local.h
rm ssl/test_values.h
rm ssl/etc
rm ssl/rule_preparer
rm ssl/token_detector
rm ssl/token_encryptor
rm ssl/tokenizer
rm ssl/tree_updater
rm ssl/util
rm include/dpi
ln -s ../../src/dpi_local.c ssl/dpi_local.c
ln -s ../../src/dpi_local.h ssl/dpi_local.h
ln -s ../../src/test_values.h ssl/test_values.h
ln -s ../../src/etc ssl/etc
ln -s ../../src/rule_preparer ssl/rule_preparer
ln -s ../../src/token_detector ssl/token_detector
ln -s ../../src/token_encryptor ssl/token_encryptor
ln -s ../../src/tokenizer ssl/tokenizer
ln -s ../../src/tree_updater ssl/tree_updater
ln -s ../../src/util ssl/util
ln -s ../../include/dpi include/dpi
