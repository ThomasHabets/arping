# $Id: Makefile 138 2000-09-15 17:22:30Z marvin $
TARGETS=arping

USE_NETIF=0
OPENBSD=0
LINUX=0
SOLARIS=0

# explicit pcap include dir is for redhat which is fux0red
CFLAGS=-g -I/usr/local/include -L/usr/local/lib -DUSE_NETIF=$(USE_NETIF) -DOPENBSD=$(OPENBSD) -DLINUX=$(LINUX) -DSOLARIS=$(SOLARIS) -I/usr/include/pcap

usage:
	@echo
	@echo "usage: make [ target ]"
	@echo "Target can be openbsd, linux or solaris"
	@echo

linux:
	make USE_NETIF=1 LINUX=1 all

openbsd:
	make OPENBSD=1 all

solaris:
	make USE_NETIF=0 SOLARIS=1 all

all: $(TARGETS)

arping.o: arping.c
	gcc -Wall $(CFLAGS) -c `libnet-config --defines` `libnet-config --cflags` arping.c

O_arping=arping.o
arping: $(O_arping)
	gcc $(CFLAGS) -g -o $@ $(O_arping) `libnet-config --libs` -lpcap

clean:
	rm -f *.o $(TARGETS)
