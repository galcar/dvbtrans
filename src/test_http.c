#include <stdio.h>

#include <sys/poll.h>

#include <string.h>

#include "http_server.h"

void web_handler (HTTP_REQUEST *request, HTTP_RESPONSE *response, void *data) {
	printf ("Handler for %s\n", request->uri);

	char buf[8192];
	char *body = "<html><body>Hello</body></html>";

	response->status=200;
	//response->reason="Not found";
	properties_add (response->headers, "Content-Type", "text/html; charset=utf-8");
	//sprintf (buf, "%d", strlen(body));
	//properties_add (response->headers, "Content-Length", buf);

	properties_add (response->headers, "Transfer-Encoding", "chunked");

	http_server_send_chunked (response, body, strlen(body));
	http_server_send_chunked (response, NULL, 0);
}

int main (int argc, char *argv[]) {

	HTTP_SERVER *server;
	HTTP_CLIENT *client;

	HTTP_REQUEST *request;
	HTTP_RESPONSE *response;

	int r;
	struct pollfd 	pfd[32];		/* the poll file descriptor table */
	int 			poll_len = 0;	/* len of pfd */
	int i;


	server = http_server_init (8181);

	pfd[poll_len].fd = server->socket;
	pfd[poll_len].events = POLLPRI | POLLIN | POLLERR;
	pfd[poll_len].revents = 0;
	poll_len++;

	while (1) {

		r = poll (pfd, poll_len, 1000);

		if (r > 0) {

			for (int i = 0; i < poll_len; i++) {

				if (pfd[i].revents & POLLPRI || pfd[i].revents & POLLIN) {

					// found file descriptor
					if (pfd[i].fd == server->socket) { // the server
						client = http_server_open_client (server);

						pfd[poll_len].fd = client->socket;
						pfd[poll_len].events = POLLPRI | POLLIN | POLLERR;
						pfd[poll_len].revents = 0;
						poll_len++;

					} else { // is a client

						client = http_server_find_client_by_fd (server, pfd[i].fd);

						request = http_server_request_new (client);

						if (request == NULL) {

							// remove from poll
							poll_len --;

							// close client
							http_server_close_client (client);
							client = NULL;

						} else {

							response = http_server_response (server, request);

							if (response != NULL) {
								web_handler (request, response, NULL);
								http_server_response_free (response);
								response = NULL;
							}

							http_server_request_free (request);
							request = NULL;
						}
					}

				}
			}

		} else if (r == 0) {
			// timeout
		} else {
			// error
		}
	}
}
