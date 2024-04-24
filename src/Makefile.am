
bin_PROGRAMS = dvbtrans test_http
dvbtrans_SOURCES = dvbtrans.h dvbtrans.c \
	tcpterm.h tcpterm.c \
	nettools.h nettools.c \
	props.h props.c \
	http_server.h http_server.c \
	dynarray.h dynarray.c \
	utils.h utils.c \
	charset.h charset.c \
	dvbviewer.h dvbviewer.c \
	recorder.h recorder.c
	
test_http_SOURCES = test_http.c \
	http_server.h http_server.c \
	props.h props.c \
	dynarray.h dynarray.c
		
dvbtrans_CFLAGS = -D_FILE_OFFSET_BITS=64