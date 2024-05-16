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
#ifndef __TCPTERM_H__
#define __TCPTERM_H__

#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>

typedef struct _tcp_server TCP_SERVER;
typedef struct _tcp_client TCP_CLIENT;

typedef enum {
	TCP_CLIENT_MODE_INIT = 0,
	TCP_CLIENT_MODE_LOGIN,
	TCP_CLIENT_MODE_PASSWORD,
	TCP_CLIENT_MODE_CMD

} tcp_client_mode_t;

struct _tcp_server {

	int socket;

	struct sockaddr_in addr;

	int clients_len;
	TCP_CLIENT* clients[10];
};


struct _tcp_client {
	int 						socket;

	struct sockaddr_in 			addr;

	char 						ip[64];
	int							dst_port;

	tcp_client_mode_t			mode;

	char						user[64];

	TCP_SERVER 					*server;

	void						*extra;

};


TCP_SERVER * tcp_server_create (int port);

void tcp_server_free (TCP_SERVER *server);



TCP_CLIENT *tcp_server_connect (TCP_SERVER *server);

TCP_CLIENT *tcp_server_get_client_by_socket (TCP_SERVER *server, int s);



void tcp_client_disconnect (TCP_CLIENT *client);

int tcp_client_read (TCP_CLIENT *client, unsigned char *buffer, int len);

void tcp_client_write (TCP_CLIENT *client, const char *format, ...);

unsigned char *tcp_client_read_ln (TCP_CLIENT *client, unsigned char *cmd);

void tcp_client_write_ln (TCP_CLIENT *client, const char *format, ...);

void tcp_client_set_extra (TCP_CLIENT *client, void *data, size_t data_size);



#endif
