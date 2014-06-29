#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ(2.61)
AC_INIT(arping, 2.14, thomas@habets.se)
AC_CANONICAL_SYSTEM
AC_CONFIG_SRCDIR([src/arping.c])
AM_INIT_AUTOMAKE
AM_MAINTAINER_MODE
AC_CONFIG_HEADER(config.h)


# Checks for programs.
AC_PROG_CC
AC_PROG_INSTALL
AC_PROG_MAKE_SET

# Checks for libraries.
AC_CHECK_LIB([m], [sqrt])
AC_CHECK_LIB([socket], [socket])
AC_CHECK_LIB([nsl], [gethostbyname])
AC_CHECK_LIB([cap], [cap_init])
AC_CHECK_LIB([rt], [clock_gettime])
AC_CHECK_LIB([net], [libnet_name_resolve],
      [AC_MSG_ERROR([libnet 1.0.x found. Arping 2.x requires libnet 1.1.x])])
AC_CHECK_LIB([net], [libnet_init], ,[AC_MSG_ERROR([libnet 1.1.x not found])])
AC_CHECK_LIB([pcap], [pcap_open_live], ,[AC_MSG_ERROR([libpcap not found])])
AC_SEARCH_LIBS([clock_gettime], [rt])

# Checks for header files.
AC_HEADER_STDC
AC_CHECK_HEADERS([\
arpa/inet.h \
netinet/in.h \
stdlib.h \
sys/socket.h \
time.h \
sys/time.h \
sys/types.h \
sys/capability.h \
stdint.h \
libnet.h \
win32/libnet.h \
net/bpf.h \
pwd.h \
unistd.h])

# Libnet include file is not optional
if test ! x$ac_cv_header_libnet_h = xyes; then
  AC_MSG_ERROR([Can't find libnet.h. See INSTALL file for where to get Libnet])
fi

# Checks for typedefs, structures, and compiler characteristics.
AC_C_CONST
AC_HEADER_TIME
AC_C_VOLATILE
AC_TYPE_UINT8_T
AC_TYPE_UINT16_T
AC_TYPE_UINT32_T
AC_TYPE_UINT64_T

# Checks for library functions.
AC_PROG_GCC_TRADITIONAL
AC_FUNC_SELECT_ARGTYPES
AC_FUNC_SETVBUF_REVERSED
AC_TYPE_SIGNAL
AC_CHECK_FUNCS([gettimeofday memset select strchr strdup strerror strstr \
getifaddrs cap_init])

if test x$ac_cv_func_getifaddrs = xyes; then
    AC_LIBOBJ([findif_getifaddrs])
else
    case "$target_os" in
        *linux*)
            AC_LIBOBJ([findif_linux])
            ;;
        *freebsd*|*openbsd*|*darwin*)
            AC_LIBOBJ([findif_sysctl])
            ;;
        *solaris*)
            AC_LIBOBJ([findif_bsdroute])
            ;;
        *)
            AC_LIBOBJ([findif_other])
            ;;
    esac
fi



# check for CLOCK_MONOTONIC
AC_CACHE_CHECK([for CLOCK_MONOTONIC],
                                  ac_cv_have_clock_monotonic, [
                                  AC_TRY_RUN(
                                        [
#include <time.h>
#include <sys/time.h>
int main() {
struct timespec ts;
exit(!!clock_gettime(CLOCK_MONOTONIC, &ts));
}
                ],
                        [ ac_cv_have_clock_monotonic="yes" ],
                        [ ac_cv_have_clock_monotonic="no" ]
                          )
])
AM_CONDITIONAL(HAVE_CLOCK_MONOTONIC, test x$ac_cv_have_clock_monotonic = xyes)
if test x$ac_cv_have_clock_monotonic = xyes; then
   AC_DEFINE([HAVE_CLOCK_MONOTONIC], [1], [Monotonic clock])
fi

AC_CONFIG_FILES([Makefile])
AC_CONFIG_FILES([src/Makefile])
AC_CONFIG_FILES([doc/Makefile])
AC_OUTPUT

echo "
  $PACKAGE_NAME version $PACKAGE_VERSION
  Prefix.........: $prefix
  Debug Build....: $debug
  C Compiler.....: $CC $CFLAGS $CPPFLAGS
  Linker.........: $LD $LDFLAGS $LIBS
"
