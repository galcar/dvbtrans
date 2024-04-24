#ifndef __TCPTERM_H__
#define __TCPTERM_H__

#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>

typedef struct _tcp_server TCP_SERVER;
typedef struct _tcp_client TCP_CLIENT;


struct _tcp_server {

	int socket;

	struct sockaddr_in addr;

	int clients_len;
	TCP_CLIENT* clients[10];
};


struct _tcp_client {
	int 						socket;

	struct sockaddr_in 			addr;

	TCP_SERVER 					*server;

	void						*extra;

};


TCP_SERVER * tcp_server_create (int port);

void tcp_server_free (TCP_SERVER *server);



TCP_CLIENT *tcp_server_connect (TCP_SERVER *server);

TCP_CLIENT *tcp_server_get_client_by_socket (TCP_SERVER *server, int s);


void tcp_client_disconnect (TCP_CLIENT *client);

int tcp_client_read (TCP_CLIENT *client, unsigned char *buffer, int len);

int tcp_client_write (TCP_CLIENT *client, unsigned char *buffer, int len);

unsigned char *tcp_client_read_ln (TCP_CLIENT *client);

void tcp_client_write_ln (TCP_CLIENT *client, const char *format, ...);

void tcp_client_set_extra (TCP_CLIENT *client, void *data, size_t data_size);



#endif
