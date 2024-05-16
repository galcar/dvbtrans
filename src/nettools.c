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
#include <netdb.h>

#include <stdio.h>

#include <stdlib.h>

#include "nettools.h"

char *get_ip_by_addr (struct sockaddr_in *addr, char *s) {

	unsigned long remote_addr = addr->sin_addr.s_addr;

	sprintf (s, "%d.%d.%d.%d",
		remote_addr & 0xff,
		remote_addr >> 8 & 0xff,
		remote_addr >> 16 & 0xff,
		remote_addr >> 24 & 0xff);

	return s;
}

char *get_ip_by_host (const char *hostname, char *ip) {

	struct hostent *he;
	int j;

	he = gethostbyname (hostname);

	if (he!=NULL && he->h_addr_list[0] != NULL) {

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
