# $Id: Makefile 737 2002-11-03 19:47:58Z marvin $
TARGETS=arping

USE_NETIF=0
OPENBSD=0
LINUX=0
SOLARIS=0
FREEBSD=0
MACOSX=0

# explicit pcap include dir is for redhat which is fux0red
CFLAGS=-g -I/usr/local/include -L/usr/local/lib -DUSE_NETIF=$(USE_NETIF) -DOPENBSD=$(OPENBSD) -DLINUX=$(LINUX) -DSOLARIS=$(SOLARIS) -DFREEBSD=$(FREEBSD) -DMACOSX=$(MACOSX) -I/usr/include/pcap

usage:
	@echo
	@echo "usage: make [ target ]"
	@echo "Target can be one of: "
	@echo "freebsd, openbsd, netbsd, linux, solaris or macosx"
	@echo
	@echo "Make doc will re-create the manpage"
	@echo "You may use make install after"
	@echo
	@echo "Important note!"
	@echo
	@echo "   Arping will only work with libnet 1.0.x, not 1.1.x"
	@echo "   BUT, arping2 will work with 1.1.x."
	@echo
	@echo "   Create the BETA arping2 by typing 'make arping2'"
	@echo "   Arping2 has been known to work on linux, I'm still working"
	@echo "   on BSD and other support."
	@echo
	@echo "   Read README for more details."
	@echo

doc: arping.yodl
	yodl2man -o arping.8 arping.yodl

linux:
	make USE_NETIF=1 LINUX=1 all

freebsd:
	make USE_NETIF=1 FREEBSD=1 all

macosx:
	make USE_NETIF=1 MACOSX=1 all

openbsd:
	make OPENBSD=1 all
netbsd:
	make openbsd

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

O_arping2=arping-2/arping.c
arping2: arping-2/arping
arping-2/arping: $(O_arping2)
	gcc -I/usr/src/Libnet-1.1.0/include -L/usr/src/Libnet-1.1.0/src -o arping arping-2/arping.c -lnet -lpcap

clean:
	rm -f *.o $(TARGETS)

distclean: clean
	rm -f config{.cache,.h,.log,.status}

maintainerclean: distclean
	rm -f config{.h.in,ure}
