# $Id: Makefile 1893 2007-07-09 22:23:28Z marvin $
TARGETS=arping

CD=cd
CP=cp
TAR=tar
GPG=gpg
MAKE=make
RM=rm
SUDO=sudo

# This is only for arping1, arping2 has it in the .c, and it should prolly
# be moved to autoconf
USE_NETIF=0
FINDIF=1
OPENBSD=0
LINUX=0
SOLARIS=0
FREEBSD=0
MACOSX=0

CC=gcc
# explicit pcap include dir is for redhat which is fux0red
CFLAGS=-g -I/usr/local/include -L/usr/local/lib -DFINDIF=$(FINDIF) -DUSE_NETIF=$(USE_NETIF) -DOPENBSD=$(OPENBSD) -DLINUX=$(LINUX) -DSOLARIS=$(SOLARIS) -DFREEBSD=$(FREEBSD) -DMACOSX=$(MACOSX) -I/usr/include/pcap -L/opt/csw/lib -R/opt/csw/lib

CFLAGS2=-g -I/usr/local/include -I/usr/local/include/libnet-1.1 -I/usr/include/pcap -I/usr/local/include/libnet11
LDFLAGS2=-g -L/usr/local/lib -L/usr/local/lib/libnet-1.1 -L/opt/csw/lib -L/usr/local/lib/libnet11

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
	$(MAKE) USE_NETIF=1 LINUX=1 FINDIF=0 arping1-make
linux:
	$(MAKE) USE_NETIF=1 LINUX=1 arping1-make

freebsd:
	$(MAKE) USE_NETIF=1 FREEBSD=1 arping1-make

macosx:
	$(MAKE) USE_NETIF=1 MACOSX=1 arping1-make

openbsd:
	$(MAKE) OPENBSD=1 arping1-make
netbsd:
	$(MAKE) openbsd

solaris:
	$(MAKE) USE_NETIF=0 SOLARIS=1 arping1-make

install:
	install -c arping /usr/local/bin/arping
	install arping.8 /usr/local/man/man8/arping.8

arping.o: arping.c
	$(CC) -Wall $(CFLAGS) -c `libnet-config --defines` `libnet-config --cflags` arping.c

O_arping=arping.o
arping1-make: $(O_arping)
	$(CC) $(CFLAGS) -g -o arping $(O_arping) `libnet-config --libs` -lpcap

SYS=$(shell uname -s)
ifeq ($(SYS),SunOS)
EXTRA_LIBS=-lsocket -lnsl
endif

O_arping2=arping-2/arping.c
arping2: arping-2/arping
arping-2/arping: $(O_arping2)
#	$(CC) `libnet-config --libs --defines --cflags` -o arping arping-2/arping.c -lnet -lpcap
	$(CC) $(CFLAGS2) $(LDFLAGS2) -o arping arping-2/arping.c -lnet -lpcap $(EXTRA_LIBS)

clean:
	rm -f *.o $(TARGETS)

distclean: clean
	rm -f config{.cache,.h,.log,.status}

V=$(shell grep version arping-2/arping.c|grep const|sed 's:[a-z =]*::;s:f;::')
DFILE=arping-$(V).tar.gz
DDIR=arping-$(V)
dist:
	($(CD) ..; \
	$(CP) -ax arping $(DDIR); \
	$(RM) -fr $(DDIR)/{.\#*,CVS,.svn,*~} \
		$(DDIR)/arping-2/{.\#*,CVS,.svn,*~}; \
	$(MAKE) -C $(DDIR) doc; \
	$(TAR) cfz $(DFILE) $(DDIR); \
	$(GPG) -b -a $(DFILE); \
	)
test: arping2
	@echo Testing with destination host=$(HOST) and MAC=$(MAC)
	@echo IF=$(IF)
#	Easy ones
	$(SUDO) ./arping -i $(IF) -c 1 -q $(HOST) || echo fail: arping host
	$(SUDO) ./arping -i $(IF) -c 1 -q $(shell $(SUDO) ./arping -i $(IF)  -c 1 -r $(HOST)) \
		|| echo fail: arping mac
	$(shell $(SUDO) ./arping -i $(IF) -c 1 -q -t 00:11:22:33:44:55 $(HOST) \
		&& echo fail: -t switch)

#	-A
	$(shell $(SUDO) ./arping -i $(IF) -c 1 -q -A $(HOST) \
		&& echo fail: -A switch)
	$(shell $(SUDO) ./arping -i $(IF) -c 1 -q -A $(MAC) \
		&& echo fail: -A switch)

#	Directed pings
	$(shell $(SUDO) ./arping -i $(IF) -c 1 -q -t $(MAC) $(HOST) \
		|| echo fail: -t switch 2)
	$(shell $(SUDO) ./arping -i $(IF) -c 1 -q -T $(HOST) $(MAC) \
		|| echo fail: -T switch)
	$(shell $(SUDO) ./arping -i $(IF) -c 1 -q -A -t $(MAC) $(HOST) \
		|| echo fail: -t switch with -A)
	$(shell $(SUDO) ./arping -i $(IF) -c 1 -q -A -T $(HOST) $(MAC) \
		|| echo fail: -T switch with -A)

#	Ok both ways?
	$(shell [ `$(SUDO) ./arping -i $(IF) -c 1 -r $(HOST)` = $(MAC) ] \
		|| echo fail: host to MAC translation weird)
	$(shell [ `$(SUDO) ./arping -i $(IF) -c 1 -R $(HOST)` = \
		  `$(SUDO) ./arping -i $(IF) -c 1 -r $(MAC)` ] \
		|| echo fail: host to MAC translation and back weird)

#	FIXME: more tests listed in arping.c

maintainerclean: distclean
	rm -f config{.h.in,ure}
