#include <stdlib.h>
#include <stdio.h>

#include <string.h>

#include <stdarg.h>

#include <unistd.h>

#include "tcpterm.h"


/**
 * create and initialize a new server at specified port
 */
TCP_SERVER * tcp_server_create (int port) {
	TCP_SERVER *server = NULL;

	int one = 1;

	server = (TCP_SERVER *) malloc (sizeof(TCP_SERVER));

	server->socket = -1;

	server->addr.sin_family = AF_INET;
	server->addr.sin_addr.s_addr = INADDR_ANY;
	server->addr.sin_port = htons( port );
	memset(&(server->addr.sin_zero), '\0', 8);

	server->clients_len = 0;


	//Create socket
	server->socket = socket(AF_INET , SOCK_STREAM , 0);
	if (server->socket == -1) {
		free (server);
		return NULL;
	}

	setsockopt(server->socket, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(int));

	//Bind
	if( bind(server->socket, (struct sockaddr *) &server->addr , sizeof(server->addr)) < 0) {
		close (server->socket);
		server->socket = -1;
		free (server);
		return NULL;
	}

	//Listen
	if (listen(server->socket , 3) < 0) {
		close (server->socket);
		server->socket = -1;
		free (server);
		return NULL;
	}

	return server;
}

/**
 * free all resources of the specified server
 */
void tcp_server_free (TCP_SERVER *server) {

	if (server == NULL) {
		return;
	}

	if (server->socket != -1) {
		close (server->socket);
		server->socket = -1;
	}

	free (server);
}


TCP_CLIENT *tcp_server_connect (TCP_SERVER *server) {

	TCP_CLIENT *client = NULL;

	int c;

	c = sizeof (struct sockaddr_in);

	client = (TCP_CLIENT *) malloc (sizeof(TCP_CLIENT));

	client->socket = accept(server->socket, (struct sockaddr *)&client->addr, (socklen_t*)&c);

	if (client->socket < 0) {
		free (client);
		return NULL;
	}

	client->server = server;
	client->extra = NULL;

	server->clients[server->clients_len] = client;
	server->clients_len ++;

	return client;

}

void tcp_client_disconnect (TCP_CLIENT *client) {

	int i, j;

	TCP_SERVER *server = NULL;

	if (client == NULL) {
		return;
	}

	server = client->server;

	if (server != NULL) {
		for (i = 0; i < server->clients_len; i++) {
			if (server->clients[i] == client) {

				server->clients_len --;

				for (j=i; j < server->clients_len; j++) {
					server->clients[j] = server->clients[j+1];
				}

				break;
			}
		}
	}

	client->server = NULL;

	close (client->socket);
	client->socket = -1;

	if (client->extra != NULL) {
		free (client->extra);
		client->extra = NULL;
	}

	free (client);
}

TCP_CLIENT *tcp_server_get_client_by_socket (TCP_SERVER *server, int s) {

	int i = 0;

	if (server == NULL) {
		return NULL;
	}

	for (i = 0; i < server->clients_len; i++) {
		if (server->clients[i]->socket == s) {
			return server->clients[i];
		}
	}

	return NULL;
}

int tcp_client_read (TCP_CLIENT *client, unsigned char *buffer, int len) {

	int n;

	n = recv(client->socket, buffer, len, 0);

	return n;

}

int tcp_client_write (TCP_CLIENT *client, unsigned char *buffer, int len) {

	int n;

	n = send (client->socket, buffer, len, 0);

	return n;
}

unsigned char *tcp_client_read_ln (TCP_CLIENT *client) {

	int n, i;

	unsigned char buffer[1024];
	unsigned char c;
	unsigned char *cmd, *p_cmd;

	n = tcp_client_read (client, buffer, 1024);

	if (n == 0) {

		return NULL;

	}

	if (n < 0) {

		cmd = (unsigned char *) malloc (1);

	} else {

		cmd = (unsigned char *) malloc (n + 1);

	}

	p_cmd = cmd;

	for (i = 0; i < n; i++) {

		c = buffer[i];

		if (c == '\n') {

		} else if (c == '\r') {

		} else {
			*p_cmd = c;
			p_cmd++;
		}
	}

	*p_cmd = '\0';

	return cmd;

}


void tcp_client_write_ln (TCP_CLIENT *client, const char *format, ...) {
	va_list ap;

	unsigned char s[1024];
	int len = 0;

	va_start(ap, format);
	vsprintf (s, format, ap);
	va_end (ap);

	sprintf (s, "%s\r\n", s);

	len = strlen (s);

	tcp_client_write (client, s, len);
}

void tcp_client_set_extra (TCP_CLIENT *client, void *data, size_t data_size) {

	if (client == NULL || data == NULL) {
		return;
	}

	if (client->extra != NULL) {
		free (client->extra);
		client->extra = NULL;
	}

	client->extra = malloc (data_size);

	memcpy (client->extra, data, data_size);

}
