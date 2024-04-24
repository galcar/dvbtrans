#ifndef _UTILS_H_
#define _UTILS_H_

static const unsigned char *EMPTY_STRING = "";

char *substring (const char *in, int n, int len);

char *replace (char *in, char c, char r);

char *to_lower (char *in);

long long current_timestamp_ms ();

char *url_decode (const char *src);

#endif
