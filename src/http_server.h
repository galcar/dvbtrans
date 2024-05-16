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
#ifndef __HTTP_SERVER_H__
#define __HTTP_SERVER_H__

#include <stdlib.h>

#include "props.h"
#include "dynarray.h"

typedef struct _http_request HTTP_REQUEST;
typedef struct _http_response HTTP_RESPONSE;
typedef struct _http_client HTTP_CLIENT;

typedef struct {
	int			socket;		// server socket descriptor

	DYN_ARRAY 	*clients; 	// list of clients

	char		*root; 		// path to the document root for http_server_send_file

} HTTP_SERVER;

struct _http_client {

	HTTP_SERVER *server;

	int 	socket;	/* client socket */
	char 	ip[64]; /* ip of the connected client */
	int		dst_port;

	void	*data;

};

struct _http_request {

	HTTP_CLIENT		*client;	// request comes from this client

	int				valid; 		// 1=valid request, 0=invalid request
	unsigned char 	*reason; 	// reason of invalid request

	unsigned char 	*method;	// method of valid request
	unsigned char 	*uri;		// uri of valid request
	unsigned char 	*version;	// version of valid request

	properties 		*headers;	// headers of valid request

	properties		*parameters;// parameters of request: from query string or post

};

struct _http_response {
	HTTP_REQUEST	*request;	// request of this response
	int 			sent;		// 0: headers not sent, 1: headers have been sent

	int 			status;		// response status code
	unsigned char 	*reason; 	// reason of status (if any)

	properties 		*headers;	// headers of response

};

HTTP_SERVER *http_server_init (int port);
void http_server_end (HTTP_SERVER *);

HTTP_CLIENT *http_server_find_client_by_fd (HTTP_SERVER *server, int fd);

HTTP_CLIENT *http_server_open_client ();
void http_server_close_client (HTTP_CLIENT *client);

HTTP_REQUEST *http_server_request_new (HTTP_CLIENT *client);
void http_server_request_free (HTTP_REQUEST *request);

HTTP_RESPONSE *http_server_response (HTTP_SERVER *server, HTTP_REQUEST *request);
void http_server_response_free (HTTP_RESPONSE *response);

int http_server_send (HTTP_RESPONSE *response, unsigned char *body, long body_len);
int http_server_send_chunked (HTTP_RESPONSE *response, unsigned char *chunk, int chunk_len);

void http_server_set_client_data (HTTP_CLIENT *client, void *data, size_t data_size);

void http_server_send_not_found (HTTP_RESPONSE *response);

void http_server_send_moved (HTTP_RESPONSE *response, char *location);

void http_server_send_file (HTTP_RESPONSE *response, unsigned char *filename);

#endif
