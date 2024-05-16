/*
 * This file is part of the dvbtrans distribution (https://github.com/galcar/dvbtrans).
 * Copyright (c) 2024 G. Alcaraz.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, version 3.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program. If not, see <http://www.gnu.org/licenses/>.
 */
#ifndef _DVBTRANS_H_
#define _DVBTRANS_H_

typedef struct _stream_output STREAM_OUTPUT;

#include <stdio.h>

#include <mydvb.h>
#include <mydvb_tune.h>
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
	int 				sockfd;
	struct sockaddr_in 	target;
} NET_OUTPUT;

typedef struct {
	FILE 				*f;
} FILE_OUTPUT;

typedef struct {
	HTTP_RESPONSE 		*response;
} HTTP_OUTPUT;

typedef struct {
	FILE 				*f;
	HTTP_RESPONSE 		*response;
	int 				listener_id;
} RECORD_OUTPUT;

struct _stream_output {
	int 				type;
	MYDVB_TUNE 			*tuner;
	union {
		NET_OUTPUT 			net_output;
		FILE_OUTPUT 		file_output;
		HTTP_OUTPUT 		http_output;
		RECORD_OUTPUT 		record_output;
	} u;
};


typedef struct {

	MYDVB_ENGINE	engine;

	char			*freq_file;

	char			*scan_file;
	INFO_DVB 		*info_dvb;
	long long		next_autoscan;

	TCP_SERVER 		*server;

	TUNER_SCAN_INFO	*scan_info;

	HTTP_SERVER 	*http;
	DYN_ARRAY		*receivers;

	RECORDER		*recorder;

	STREAM_OUTPUT	*broadcast;

} APP_INFO;

MYDVB_TUNE *tuner_program (MYDVB_ENGINE *engine, INFO_PROGRAM *ip);

void record_stream_callback (MYDVB_ENGINE *engine, MYDVB_EVENT *event, void *data);

#endif
