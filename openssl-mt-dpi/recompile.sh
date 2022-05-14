#!/bin/bash

rm ../lib/libcrypto.*
rm ../lib/libssl.*

make

cp libcrypto.a ../lib
cp libcrypto.so* ../lib
cp libssl.a ../lib
cp libssl.so* ../lib
cp -rf include/openssl/* ../include/openssl
