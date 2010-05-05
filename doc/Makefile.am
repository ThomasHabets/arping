# arping/doc/Makefile.am
#
include $(top_srcdir)/Makefile.am.common

# Manpage is only run by maintainer, not by end user. That's why there
# is no dependency on arping.yodl.
man_MANS = arping.8
arping.8:
	yodl2man -o arping.8.tmp arping.yodl
	perl -ne 's/(^|(?<=[^\\\w]))-/\\-/g;print' < arping.8.tmp > arping.8
	rm -f arping.8.tmp
