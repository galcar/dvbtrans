#ifndef _DVBTRANS_H_
#define _DVBTRANS_H_

typedef union _stream_output STREAM_OUTPUT;

#include <stdio.h>

#include <mydvb.h>
#include <mydvb_info_dvb.h>

#include "tcpterm.h"
#include "dynarray.h"
#include "http_server.h"

#include "recorder.h"

/**
 * Data definitions
 */

#define OUTPUT_TYPE_NET 	1
#define OUTPUT_TYPE_FILE 	2
#define OUTPUT_TYPE_HTTP	3
#define OUTPUT_TYPE_RECORD	4

/**
 * Data structures
 */


typedef struct {
	int type;
	int sockfd;
	struct sockaddr_in target;
} NET_OUTPUT;

typedef struct {
	int type;
	FILE *f;
} FILE_OUTPUT;

typedef struct {
	int type;
	HTTP_RESPONSE *response;
} HTTP_OUTPUT;

typedef struct {
	int type;
	FILE *f;
	HTTP_RESPONSE *response;
	int listener_id;
} RECORD_OUTPUT;

union _stream_output {
	int type;
	NET_OUTPUT net_output;
	FILE_OUTPUT file_output;
	HTTP_OUTPUT http_output;
	RECORD_OUTPUT record_output;
};


typedef struct {

	MYDVB 			*mydvb;

	char			*freq_file;

	char			*scan_file;
	INFO_DVB 		*info_dvb;

	TCP_SERVER 		*server;

	int 			channumber;
	int 			number;

	TUNE_SCAN_INFO	*scan_info;

	HTTP_SERVER 	*http;
	DYN_ARRAY		*receivers;

	RECORDER		*recorder;

} APP_INFO;

void record_stream_callback (MYDVB *mydvb, MYDVB_EVENT *event, void *data);

#endif
