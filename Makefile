# $Id: Makefile 97 2000-08-13 16:06:31Z marvin $
TARGETS=arping

USE_NETIF=0
OPENBSD=0
LINUX=0

CFLAGS=-g -I/usr/local/include -L/usr/local/lib -DUSE_NETIF=$(USE_NETIF) -DOPENBSD=$(OPENBSD) -DLINUX=$(LINUX)

usage:
	@echo
	@echo "usage: (g)make [ target ]"
	@echo "Target can be openbsd or linux"
	@echo

linux:
	make USE_NETIF=1 LINUX=1 all

openbsd:
	gmake OPENBSD=1 all


all: $(TARGETS)

%.o: %.c
	gcc -Wall $(CFLAGS) -c `libnet-config --defines` `libnet-config --cflags` $<

O_arping=arping.o
arping: $(O_arping)
	gcc $(CFLAGS) -g -o $@ $(O_arping) `libnet-config --libs` -lpcap

clean:
	rm -f *.o $(TARGETS)
