# $Id: Makefile 416 2001-09-05 21:42:53Z marvin $
TARGETS=arping

USE_NETIF=0
OPENBSD=0
LINUX=0
SOLARIS=0
FREEBSD=0

# explicit pcap include dir is for redhat which is fux0red
CFLAGS=-g -I/usr/local/include -L/usr/local/lib -DUSE_NETIF=$(USE_NETIF) -DOPENBSD=$(OPENBSD) -DLINUX=$(LINUX) -DSOLARIS=$(SOLARIS) -DFREEBSD=$(FREEBSD) -I/usr/include/pcap

usage:
	@echo
	@echo "usage: make [ target ]"
	@echo "Target can be freebsd, openbsd, linux or solaris"
	@echo
	@echo "Make doc will re-create the manpage"
	@echo "You may use make install after"
	@echo

doc: arping.yodl
	yodl2man -o arping.8 arping.yodl

linux:
	make USE_NETIF=1 LINUX=1 all

freebsd:
	make USE_NETIF=1 FREEBSD=1 all

openbsd:
	make OPENBSD=1 all

solaris:
	make USE_NETIF=0 SOLARIS=1 all

install:
	install -c arping /usr/local/bin/arping
	install arping.8 /usr/local/man/man8/arping.8

all: $(TARGETS)

arping.o: arping.c
	gcc -Wall $(CFLAGS) -c `libnet-config --defines` `libnet-config --cflags` arping.c

O_arping=arping.o
arping: $(O_arping)
	gcc $(CFLAGS) -g -o $@ $(O_arping) `libnet-config --libs` -lpcap

clean:
	rm -f *.o $(TARGETS)
