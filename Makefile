# $Id: Makefile 984 2003-08-07 20:11:36Z marvin $
TARGETS=arping

USE_NETIF=0
FINDIF=1
OPENBSD=0
LINUX=0
SOLARIS=0
FREEBSD=0
MACOSX=0

CC=gcc
# explicit pcap include dir is for redhat which is fux0red
CFLAGS=-g -I/usr/local/include -L/usr/local/lib -DFINDIF=$(FINDIF) -DUSE_NETIF=$(USE_NETIF) -DOPENBSD=$(OPENBSD) -DLINUX=$(LINUX) -DSOLARIS=$(SOLARIS) -DFREEBSD=$(FREEBSD) -DMACOSX=$(MACOSX) -I/usr/include/pcap

all: message arping2

message:
	@echo ""
	@echo "Will now try to compile arping 2.x. If you have Libnet 1.0.x"
	@echo "(as opposed to 1.1.x) then this will fail and you should try"
	@echo "compiling arping 1.x."
	@echo ""
	@echo "Note that arping 1.x has been tested *A LOT* more than "
	@echo "arping 2.x, so if you have problems (especially compilation"
	@echo "problems), then try arping 1.x with libnet 1.0.x. Also, mail"
	@echo "me about it. thomas@habets.pp.se"
	@echo ""
	@echo "For information on how to compile arping 1.x, type "
	@echo "'make arping1'"
	@echo ""
	sleep 3

arping1:
	@echo
	@echo "usage: make [ target ]"
	@echo "Target can be one of: "
	@echo "freebsd, openbsd, netbsd, linux, solaris or macosx"
	@echo
	@echo "Important note!"
	@echo
	@echo "   Arping 1.x will only work with libnet 1.0.x, not 1.1.x"
	@echo "   BUT, arping 2.x will work with 1.1.x."
	@echo
	@echo "   Create arping 2.x by typing 'make'"
	@echo "   Arping 2.x has been known to work most architectures"
	@echo "   that arping 1.x works on, but arping 1.x has been tested"
	@echo "   more"
	@echo
	@echo "   Read README for more details."
	@echo

doc: arping.yodl
	yodl2man -o arping.8 arping.yodl

linux-nofindif:
	make USE_NETIF=1 LINUX=1 FINDIF=0 arping1-make
linux:
	make USE_NETIF=1 LINUX=1 arping1-make

freebsd:
	make USE_NETIF=1 FREEBSD=1 arping1-make

macosx:
	make USE_NETIF=1 MACOSX=1 arping1-make

openbsd:
	make OPENBSD=1 arping1-make
netbsd:
	make openbsd

solaris:
	make USE_NETIF=0 SOLARIS=1 arping1-make

install:
	install -c arping /usr/local/bin/arping
	install arping.8 /usr/local/man/man8/arping.8

arping.o: arping.c
	$(CC) -Wall $(CFLAGS) -c `libnet-config --defines` `libnet-config --cflags` arping.c

O_arping=arping.o
arping1-make: $(O_arping)
	$(CC) $(CFLAGS) -g -o arping $(O_arping) `libnet-config --libs` -lpcap

O_arping2=arping-2/arping.c
arping2: arping-2/arping
arping-2/arping: $(O_arping2)
	$(CC) `libnet-config --libs --defines --cflags` -o arping arping-2/arping.c -lnet -lpcap

clean:
	rm -f *.o $(TARGETS)

distclean: clean
	rm -f config{.cache,.h,.log,.status}

maintainerclean: distclean
	rm -f config{.h.in,ure}
