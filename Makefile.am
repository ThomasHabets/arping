# arping/Makefile.am
#
include $(top_srcdir)/Makefile.am.common

SUBDIRS=src doc

tarball:
	./extra/mktarball latest

mrproper: maintainer-clean
	rm -f aclocal.m4 configure.scan depcomp missing install-sh config.h.in
	rm -f Makefile.in configure autoscan*.log config.guess config.sub
	rm -f ltmain.sh configure.in src/Makefile.in doc/Makefile.in
