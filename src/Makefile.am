# arping/src/Makefile.am

include $(top_srcdir)/Makefile.am.common
CFLAGS+= $(EXTRA_CFLAGS)

include_HEADERS=arping.h

sbin_PROGRAMS = arping
noinst_PROGRAMS = fuzz_pingip

arping_SOURCES = arping.c arping_main.c unix.c cast.c
arping_LDADD = $(LIBOBJS)

fuzz_pingip_SOURCES = arping.c fuzz_pingip.c unix.c mock_libpcap.c mock_libnet.c cast.c
fuzz_pingip_LDADD = $(LIBOBJS)

TESTS=arping_test
check_PROGRAMS=arping_test
arping_test_SOURCES=arping.c arping_test.c unix.c mock_libpcap.c mock_libnet.c cast.c
arping_test_LDADD=$(LIBOBJS) -lcheck -lpthread -lsubunit

#cast.h cast.c: mkcast.py
#	./mkcast.py
