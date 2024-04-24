
#include <netdb.h>

#include <stdio.h>

#include <stdlib.h>

#include "nettools.h"

char *get_ip_by_addr (struct sockaddr_in *addr) {

	static char s[16];

	unsigned long remote_addr = addr->sin_addr.s_addr;

	sprintf (s, "%d.%d.%d.%d",
		remote_addr & 0xff,
		remote_addr >> 8 & 0xff,
		remote_addr >> 16 & 0xff,
		remote_addr >> 24 & 0xff);

	return s;
}

char *get_ip_by_host (const char *hostname) {

	char *ip;

	struct hostent *he;
	int j;

	he = gethostbyname (hostname);

	if (he!=NULL && he->h_addr_list[0] != NULL) {

		ip = (char *) malloc (16); /* ipv4 address */

		sprintf (ip, "");

		for (j=0; j < he->h_length; j++) {

			sprintf (ip, "%s%d", ip, (unsigned char) he->h_addr_list[0][j]);

			if (j < he->h_length - 1) {
				sprintf (ip, "%s.", ip);
			}
		}

		return ip;

	} else {

		return NULL;
	}
}
