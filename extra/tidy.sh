#!/usr/bin/env bash

set -e

# src/findif_bsdroute.c
# src/windows.c
# src/findif_linux.c
# src/findif_sysctl.c
for f in src/arping.c \
	     src/arping_main.c \
	     src/arping_test.c \
	     src/cast.c \
	     src/findif_getifaddrs.c \
	     src/findif_other.c \
	     src/fuzz_pingip.c \
	     src/fuzz_pingmac.c \
	     src/mock_libnet.c \
	     src/mock_libpcap.c \
	     src/unix.c; do
    echo "========================================================="
    echo "Checking ${f?}…"
    clang-tidy "${f?}" -- -DHAVE_CONFIG_H -I. -I..   -D_DEFAULT_SOURCE=1 -std=c99
done
