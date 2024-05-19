
bin_PROGRAMS = test_http

test_http_SOURCES = test_http.c \
	../src/http_server.h ../src/http_server.c \
	../src/props.h ../src/props.c \
	../src/dynarray.h ../src/dynarray.c \
	../src/nettools.h ../src/nettools.c

test_http_CPPFLAGS = -I$(top_srcdir)/../libmydvb/include -I$(top_srcdir)/src
test_http_CFLAGS = -D_FILE_OFFSET_BITS=64 -L$(top_srcdir)/../libmydvb/build/src/.libs
