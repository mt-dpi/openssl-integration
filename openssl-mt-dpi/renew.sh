#!/bin/bash

if [[ $# -gt 1 ]]
then
  echo "Invalid argument: ./renew.sh <prefix>"
  exit 1
fi 

./clean.sh

if [[ $# == 1 ]] 
then
  ./config --prefix=$1
else
  ./config
fi

make

cp libcrypto.a ../lib
cp libcrypto.so* ../lib
cp libssl.a ../lib
cp libssl.so* ../lib
cp -rf include/openssl/* ../include/openssl
