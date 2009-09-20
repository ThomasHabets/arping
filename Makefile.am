# arping/Makefile.am

AUTOMAKE_OPTIONS = foreign

sbin_PROGRAMS = arping
man_MANS = arping.8
arping_SOURCES = src/arping.c

doc:
	yodl2man -o arping.8 src/arping.yodl

mrproper: maintainer-clean
	rm -f aclocal.m4 configure.scan depcomp missing install-sh config.h.in
	rm -f Makefile.in configure autoscan*.log config.guess config.sub
	rm -f ltmain.sh configure.in
