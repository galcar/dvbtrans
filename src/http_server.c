
#include <sys/types.h>
#include <sys/socket.h>

#include <netinet/in.h>

#include <arpa/inet.h>

#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <errno.h>

#include "http_server.h"

#define BUFFER_SIZE 1024*1024

void __http_server_client_free (void *p) {

	HTTP_CLIENT *client = *((HTTP_CLIENT **) p);

	if (client == NULL) {
		return;
	}

	close (client->socket);
	client->socket = -1;
	client->server = NULL;
	if (client->data != NULL) {
		free (client->data);
		client->data = NULL;
	}

	free (client);
}

HTTP_SERVER *http_server_init (int port) {

	int server_fd;
	struct sockaddr_in server_addr;
	HTTP_SERVER *server;

	int one = 1;

	if ((server_fd = socket (AF_INET, SOCK_STREAM, 0)) < 0) {
		// error
		printf ("Error creating http socket %s\n", strerror(errno));
		return NULL;
	}

	setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(int));

	server_addr.sin_family = AF_INET;
	server_addr.sin_addr.s_addr = INADDR_ANY;
	server_addr.sin_port = htons (port);

	if (bind(server_fd, (struct sockaddr *) &server_addr, sizeof(server_addr)) < 0) {
		// error
		printf ("Error binding server %s\n", strerror(errno));
		close (server_fd);
		return NULL;
	}

	if (listen (server_fd, 10) < 0) {
		// error
		printf ("Error listening server %s\n", strerror(errno));
		close (server_fd);
		return NULL;
	}

	server = (HTTP_SERVER *) malloc (sizeof (HTTP_SERVER));

	server->socket 		= server_fd;
	server->clients		= dyn_array_new (sizeof(HTTP_CLIENT *));
	server->root		= NULL;
	dyn_array_set_free_callback (server->clients, __http_server_client_free);

	return server;
}

void http_server_end (HTTP_SERVER *server) {

	if (server == NULL) {
		return;
	}
	close(server->socket);
	server->socket	= -1;

	dyn_array_free (server->clients);

	server->clients = NULL;

	free (server);
}

HTTP_CLIENT *http_server_find_client_by_fd (HTTP_SERVER *server, int fd) {
	int i;
	HTTP_CLIENT *client;

	if (server == NULL) {
		return NULL;
	}

	for (i=0; i < dyn_array_get_size(server->clients); i++) {
		client = *((HTTP_CLIENT **) dyn_array_get_data (server->clients, i));
		if (client == NULL) {
			continue;
		}
		if (client->socket == fd) {
			return client;
		}
	}

	return NULL;
}

HTTP_CLIENT *http_server_open_client (HTTP_SERVER *server) {

	struct sockaddr_in client_addr;
	socklen_t client_addr_len = sizeof(client_addr);
	HTTP_CLIENT *client = NULL;

	int client_socket_fd = accept (server->socket
			,(struct sockaddr *) &client_addr
			, &client_addr_len);

	client = (HTTP_CLIENT *) malloc (sizeof(HTTP_CLIENT));

	client->server = server;
	client->socket = client_socket_fd;
	client->data   = NULL;

	dyn_array_add (server->clients, &client);

	//printf ("Added client. Clients size %d\n", dyn_array_get_size(server->clients));

	return client;
}

void http_server_close_client (HTTP_CLIENT *client) {
	int i;
	HTTP_CLIENT *aux;
	HTTP_SERVER *server;

	if (client == NULL) {
		return;
	}

	server = client->server;

	if (server == NULL) {
		return;
	}

	// remove from list of server clients
	for (i=0; i < dyn_array_get_size (server->clients); i++) {
		aux = *((HTTP_CLIENT **) dyn_array_get_data (server->clients, i));
		if (aux == client) {
			__http_server_client_free ((HTTP_CLIENT *) dyn_array_get_data (server->clients, i));

			dyn_array_remove (server->clients, i);
			//printf ("Removed client. Clients size: %d\n", dyn_array_get_size(server->clients));
			break;
		}
	}
}

/**
 * return a new request from client or NULL if client has been disconnected
 */
HTTP_REQUEST *http_server_request_new (HTTP_CLIENT *client) {

	HTTP_REQUEST *request = NULL;

	unsigned char *buffer;
	ssize_t bytes_received;

	int status = 0;
	int pos = 0;
	unsigned char *l_start;

	unsigned char *header_key;

	buffer = (unsigned char *) malloc (BUFFER_SIZE);

	bytes_received = recv(client->socket, buffer, BUFFER_SIZE, 0);

	if (bytes_received == 0) { // disconnect from client
		request = NULL;

	} else if (bytes_received < 0) {
		//printf ("--Request ERROR %s\n", strerror(errno)); // Bad file descriptor, closed by peer
		request = NULL;

	} else if (bytes_received > 0) {

		// parse received data
		request = (HTTP_REQUEST *) malloc (sizeof(HTTP_REQUEST));

		request->client		= client;
		request->valid		= 1;
		request->reason		= NULL;
		request->method 	= NULL;
		request->uri 		= NULL;
		request->version 	= NULL;
		request->headers 	= properties_new ();
		request->parameters = properties_new ();

		status = 0;
		l_start = buffer;
		pos = 0;
		while (pos < bytes_received) {

			if (status == 0) {

				if (buffer[pos] == ' ') {
					buffer[pos] = '\0';
					request->method = strdup (l_start);
					l_start = &buffer[pos+1];
					status = 1;
				}

			} else if (status == 1) {

				if (buffer[pos] == ' ') {
					// end of line of request line
					buffer[pos] = '\0'; // null string terminator
					request->uri = strdup (l_start);
					l_start = &buffer[pos+1];
					status = 2;

				} else if (buffer[pos] == '?') { // end of uri and start parameters
					buffer[pos] = '\0'; // null string terminator
					request->uri = strdup (l_start);
					l_start = &buffer[pos+1];
					status = 4;
				}

			} else if (status == 2) {
				if (buffer[pos] == '\r') {
					status = 3;
				}

			} else if (status == 3) {
				if (buffer[pos] == '\n') {
					buffer[pos-1] = '\0';
					request->version = strdup (l_start);
					l_start = &buffer[pos+1];
					status = 10;
				}

			} else if (status == 4) { // status 4,5: read query string parameters

				if (buffer[pos] == '=') {
					buffer[pos] = '\0';
					header_key = l_start;
					l_start=&buffer[pos+1];
					status = 5;

				} else if (buffer[pos] == ' ') {
					buffer[pos] = '\0';
					l_start = &buffer[pos+1];
					status = 2;
				}

			} else if (status == 5) {

				if (buffer[pos] == '&') {
					buffer[pos] = '\0';

					properties_add (request->parameters
							, header_key
							, l_start);

					l_start = &buffer[pos+1];
					status = 4;

				} else if (buffer[pos] == ' ') {
					buffer[pos] = '\0';
					properties_add (request->parameters
								, header_key
								, l_start);

					l_start = &buffer[pos+1];
					status = 2;
				}

			} else if (status == 10) {

				if (buffer[pos] == ':') {
					buffer[pos] = '\0';
					header_key = l_start;
					l_start = &buffer[pos+1];
					status = 11;

				} else if (buffer[pos] == '\r') {
					status = 13;
				}

			} else if (status == 11) {

				if (buffer[pos] == '\r') {
					status = 13;
				} else if (buffer[pos] == ' ') {
					l_start ++;
				} else {
					status = 12;
				}

			} else if (status == 12) {
				if (buffer[pos] == '\r') {
					status = 13;
				}

			} else if (status == 13) {

				if (buffer[pos] == '\n') {
					// end of line of header line
					buffer[pos-1] = '\0';

					if (strcmp(l_start,"")==0) {
						//printf ("Empty line, end of header\n");
						status = 20;

					} else {

						properties_add (request->headers
								, header_key
								, l_start);
						//printf ("--Header: %s=%s\n", header_key, l_start);
						l_start = &buffer[pos+1];
						status = 10;
					}
				}
			} else if (status == 20) {
				//printf ("%X ", buffer[pos]);
			}
			pos ++;
		}

		/*
		printf ("Request client header line: %s %s %s\n", request->method, request->uri, request->version);
		for (pos = 0 ; pos < properties_size (request->headers); pos++) {
			property *p = properties_get_at (request->headers, pos);
			printf ("--Header %s=%s\n", p->key, p->value);
		}
		for (pos = 0 ; pos < properties_size (request->parameters); pos++) {
			property *p = properties_get_at (request->parameters, pos);
			printf ("--Parameter %s=%s\n", p->key, p->value);
		}
		 */

		//printf ("End of request\n");
	}

	free (buffer);

	return request;
}

void http_server_request_free (HTTP_REQUEST *request) {
	if (request->method != NULL) {
		free (request->method);
		request->method = NULL;
	}
	if (request->uri != NULL) {
		free (request->uri);
		request->uri = NULL;
	}
	if (request->version != NULL) {
		free (request->version);
		request->version = NULL;
	}
	properties_free(request->headers);
	request->headers = NULL;

	properties_free(request->parameters);
	request->parameters = NULL;

	free (request);

}

int __http_server_send_header (HTTP_RESPONSE *response) {
	int n;
	char buf[8192];

	int i;

	// send response status line
	sprintf (buf, "HTTP/1.1 %d %s\r\n", response->status, response->reason);
	n = send (response->request->client->socket, buf, strlen(buf), 0);
	if (n==-1) {
		return -1;
	}

	// send headers
	for (i=0; i < properties_size (response->headers); i++) {
		property *pv = properties_get_at (response->headers, i);

		sprintf (buf, "%s: %s\r\n", pv->key, pv->value);

		//printf ("Response header %s\n", buf);

		n = send (response->request->client->socket, buf, strlen(buf), 0);
		if (n==-1) {
			return -1;
		}
	}

	// send end of header
	sprintf (buf, "\r\n");
	n = send (response->request->client->socket, buf, strlen(buf), 0);
	if (n==-1) {
		return -1;
	}

	response->sent = 1;

	return 0;
}

HTTP_RESPONSE *http_server_response (HTTP_SERVER *server, HTTP_REQUEST *request) {

	HTTP_RESPONSE *response;

	response = (HTTP_RESPONSE *) malloc (sizeof (HTTP_RESPONSE));

	response->request	= request;
	response->sent 		= 0;

	response->status 	= 0;
	response->reason 	= NULL;
	response->headers 	= properties_new();

	if (request->valid == 0) {
		response->status = 400;
		response->reason = "Bad Request";

		__http_server_send_header (response);

		http_server_response_free (response);
		response = NULL;
	}

	return response;
}

void http_server_response_free (HTTP_RESPONSE *response) {
	properties_free (response->headers);
	response->headers = NULL;

	response->request = NULL;

	free (response);
}

int http_server_send (HTTP_RESPONSE *response, unsigned char *body, long body_len) {
	unsigned char *chunk_ptr;
	long total_send = 0;
	int chunk_len;
	int n;

	if (!response->sent) {
		if (__http_server_send_header (response) < 0) {
			return -1;
		}
	}

	chunk_ptr = body;
	total_send = 0;
	while (total_send < body_len) {

		chunk_len = (body_len - total_send) > 8192 ? 8192 : (body_len - total_send);

		n = send (response->request->client->socket, chunk_ptr, chunk_len,0);
		if (n < 0) {
			return -1;
		}

		chunk_ptr += n;

		total_send += n;

	}

	return total_send;
}

int http_server_send_chunked (HTTP_RESPONSE *response, unsigned char *chunk, int chunk_len) {
	char ssize[16];

	if (!response->sent) {
		if (__http_server_send_header (response) < 0) {
			return -1;
		}
	}

	if (chunk_len == 0) {

		// no more chunks
		if (send (response->request->client->socket, "0\r\n\r\n", 5, 0) < 0) {
			return -1;
		}

	} else {
		sprintf (ssize, "%X\r\n", chunk_len);
		if (send (response->request->client->socket, ssize, strlen(ssize), 0) < 0) {
			return -1;
		}

		if (send (response->request->client->socket, chunk, chunk_len, 0) < 0) {
			return -1;
		}

		if (send (response->request->client->socket, "\r\n", 2, 0) < 0) {
			return -1;
		}
	}

	return chunk_len;

}

void http_server_set_client_data (HTTP_CLIENT *client, void *data, size_t data_size) {

	if (client == NULL || data == NULL) {
		return;
	}

	if (client->data != NULL) {
		free (client->data);
		client->data = NULL;
	}

	client->data = malloc (data_size);

	memcpy (client->data, data, data_size);

}

void http_server_send_not_found (HTTP_RESPONSE *response) {
	response->status=404;
	response->reason="Not found";

	http_server_send (response, NULL, 0);
}

void http_server_send_moved (HTTP_RESPONSE *response, char *location) {
	response->status = 301;
	response->reason = "Moved Permanently";

	properties_add (response->headers, "Location", location);

	http_server_send (response, NULL, 0);

}

void http_server_send_file (HTTP_RESPONSE *response, unsigned char *filename) {
	unsigned char ssize[16];

	FILE *f;
	size_t size_n;

	char buffer[8192];

	if (filename == NULL || response->request->client->server->root == NULL) {

		http_server_send_not_found (response);

		return;
	}

	sprintf (buffer, "%s/%s", response->request->client->server->root, filename);

	f = fopen (buffer, "r");

	if (f) {

		/* get the size of the file */
		fseek(f, 0L, SEEK_END);
		size_n = ftell(f);
		fseek(f, 0L, SEEK_SET);

		response->status=200;
		response->reason="OK";

		properties_add (response->headers, "Content-Type", "image/png");

		sprintf (ssize, "%d", size_n);
		properties_add (response->headers, "Content-Length", ssize);

		if (strcmp("HEAD",response->request->method)==0) {

			http_server_send (response, NULL, 0);

		} else {

			while (!feof(f)) {
				size_n = fread (buffer, 1, sizeof(buffer), f);
				http_server_send (response, buffer, size_n);
			}
		}

		fclose (f);

	} else {

		http_server_send_not_found (response);
	}
}

