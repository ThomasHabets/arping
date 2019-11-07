#!/usr/bin/env bash
set -e

./bootstrap.sh

for std in c99 c11 c18; do
  for cc in gcc clang; do
    ./configure --prefix=$HOME/opt/libnet CFLAGS="-std=$std -Wall -Wextra -pedantic -O3 -march=native" CC=$cc
    make clean
    make -j8 EXTRA_CFLAGS="-Werror"
    make check 2>/dev/null || (echo "Test failed" && exit 1)
  done
done
