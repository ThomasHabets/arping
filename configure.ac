#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ(2.61)
AC_INIT(arping, 2.08, thomas@habets.pp.se)
AC_CONFIG_SRCDIR([arping.c])
AM_INIT_AUTOMAKE
AM_MAINTAINER_MODE
AC_CONFIG_HEADER(config.h)


# Checks for programs.
AC_PROG_CC
AC_PROG_INSTALL
AC_PROG_MAKE_SET

# Checks for libraries.
# FIXME: Replace `main' with a function in `-lnet':
AC_CHECK_LIB([net], [libnet_init])
# FIXME: Replace `main' with a function in `-lnsl':
AC_CHECK_LIB([nsl], [main])
# FIXME: Replace `main' with a function in `-lpcap':
AC_CHECK_LIB([pcap], [pcap_open_live])
# FIXME: Replace `main' with a function in `-lsocket':
AC_CHECK_LIB([socket], [socket])

# Checks for header files.
AC_HEADER_STDC
AC_CHECK_HEADERS([
arpa/inet.h
netinet/in.h
stdlib.h
sys/socket.h
sys/time.h
unistd.h])

# Checks for typedefs, structures, and compiler characteristics.
AC_C_CONST
AC_HEADER_TIME
AC_C_VOLATILE

# Checks for library functions.
AC_PROG_GCC_TRADITIONAL
AC_FUNC_MEMCMP
AC_FUNC_SELECT_ARGTYPES
AC_FUNC_SETVBUF_REVERSED
AC_TYPE_SIGNAL
AC_CHECK_FUNCS([gettimeofday memset select strchr strdup strerror strstr])

AC_CONFIG_FILES([Makefile])
AC_OUTPUT
