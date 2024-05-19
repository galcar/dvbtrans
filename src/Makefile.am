
bin_PROGRAMS = dvbtrans
dvbtrans_SOURCES = dvbtrans.h dvbtrans.c \
	tcpterm.h tcpterm.c \
	nettools.h nettools.c \
	props.h props.c \
	http_server.h http_server.c \
	dynarray.h dynarray.c \
	utils.h utils.c \
	dvbviewer.h dvbviewer.c \
	recorder.h recorder.c

		
# dvbtrans_CFLAGS = -D_FILE_OFFSET_BITS=64

dvbtrans_CPPFLAGS = -I$(top_srcdir)/../libmydvb/include
dvbtrans_CFLAGS = -D_FILE_OFFSET_BITS=64 -L$(top_srcdir)/../libmydvb/build/src/.libs
 