#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ([2.69])
AC_INIT([dvbtrans], [0.1.0], [Bugs <bugs@galcaraz.com>])
AC_CONFIG_SRCDIR([src/dvbtrans.c])
AC_CONFIG_HEADERS([config.h])


AM_INIT_AUTOMAKE

# Checks for C compiler
AC_PROG_CC


# Checks for header files.
AC_CHECK_HEADERS([arpa/inet.h netdb.h netinet/in.h stdlib.h string.h sys/socket.h unistd.h])

# Checks for typedefs, structures, and compiler characteristics.
AC_TYPE_PID_T

# Checks for library functions.
AC_FUNC_FORK
AC_FUNC_MALLOC
AC_FUNC_MKTIME
AC_CHECK_FUNCS([bzero gethostbyname memset select socket strdup strerror strrchr strstr])

# Checks for libraries.
AC_SEARCH_LIBS([mydvb_engine_init], [mydvb], [], [
  AC_MSG_ERROR([unable to find the mydvb library])
])

AC_CONFIG_FILES([Makefile
                 doc/Makefile
                 m4/Makefile
                 src/Makefile
                 tests/Makefile])

AC_OUTPUT
