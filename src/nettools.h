#ifndef __NETTOOLS_H__
#define __NETTOOLS_H__

#include <sys/types.h>

char *get_ip_by_addr (struct sockaddr_in *addr);

char *get_ip_by_host (const char *hostname);

#endif
