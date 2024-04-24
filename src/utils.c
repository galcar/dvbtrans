
#include <ctype.h>

#include <stddef.h>

#include <stdlib.h>

#include <string.h>

#include <sys/time.h>


char *substring (const char *in, int n, int len) {

	int i;
	char *aux;

	if (in == NULL) {
		return NULL;
	}

	aux = (char *) malloc (len+1);

	in += n;
	for (i=0; i < len; i++) {
		aux[i] = *in++;
	}
	aux[i] = '\0';

	return aux;
}

char *replace (char *in, char c, char r) {
	char *aux = in;

	if (in == NULL) {
		return NULL;
	}

	while (*in != '\0') {
		if (*in == c) {
			*in = r;
		}
		in++;
	}

	return aux;
}

char *to_lower (char *in) {

	char *out = in;
	char *aux = in;

	if (in == NULL) {
		return NULL;
	}

	while (*in != '\0') {
		*aux++ = tolower (*in++);
	}
	*aux = '\0';

	return out;

}

/**
 * return current time in ms
 */
long long current_timestamp_ms () {
    static struct timeval tv;

    gettimeofday(&tv, NULL); // get current time

    long long ms = tv.tv_sec*1000LL + tv.tv_usec/1000; // calculate milliseconds

    return ms;
}

char *url_decode (const char *src) {

	char a, b;

	char *s = (char *) malloc (strlen(src)+1);

	char *dst = s;

	while (*src) {
		if ((*src == '%') &&
            ((a = src[1]) && (b = src[2])) &&
            (isxdigit(a) && isxdigit(b))) {
			if (a >= 'a')
				a -= 'a'-'A';
			if (a >= 'A')
				a -= ('A' - 10);
			else
				a -= '0';
			if (b >= 'a')
				b -= 'a'-'A';
			if (b >= 'A')
				b -= ('A' - 10);
			else
				b -= '0';

			*dst++ = 16*a+b;
			src+=3;

		} else if (*src == '+') {
			*dst++ = ' ';
			src++;

		} else {
			*dst++ = *src++;
		}
	}

	*dst++ = '\0';

	return s;
}
