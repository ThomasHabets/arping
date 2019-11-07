#!/usr/bin/env bash
set -e

./bootstrap.sh

for std in c99 c11 c18; do
  for cc in gcc clang; do
    cppflags="-I$HOME/opt/libnet/include"
    ldflags="-L$HOME/opt/libnet/lib -Wl,-rpath -Wl,$HOME/opt/libnet/lib"
    cflags="-std=$std -Wall -Wextra -pedantic -O3 -march=native"
    ./configure --prefix="$HOME/opt/arping" \
      CPPFLAGS="$cppflags" \
      CFLAGS="$cflags" \
      LDFLAGS="$ldflags" \
      CC=$cc
    make clean
    make -j8 EXTRA_CFLAGS="-Werror"
    make check 2>/dev/null || (echo "Test failed" && exit 1)
  done
done
