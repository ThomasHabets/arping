# $Id: Makefile 131 2000-09-11 21:46:58Z marvin $
TARGETS=arping

USE_NETIF=0
OPENBSD=0
LINUX=0

# explicit pcap include dir is for redhat which is fux0red
CFLAGS=-g -I/usr/local/include -L/usr/local/lib -DUSE_NETIF=$(USE_NETIF) -DOPENBSD=$(OPENBSD) -DLINUX=$(LINUX) -I/usr/include/pcap

usage:
	@echo
	@echo "usage: make [ target ]"
	@echo "Target can be openbsd or linux"
	@echo

linux:
	make USE_NETIF=1 LINUX=1 all

openbsd:
	make OPENBSD=1 all


all: $(TARGETS)

arping.o: arping.c
	gcc -Wall $(CFLAGS) -c `libnet-config --defines` `libnet-config --cflags` arping.c

O_arping=arping.o
arping: $(O_arping)
	gcc $(CFLAGS) -g -o $@ $(O_arping) `libnet-config --libs` -lpcap

clean:
	rm -f *.o $(TARGETS)
