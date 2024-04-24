#ifndef _CHARSET_H_
#define _CHARSET_H_

#include <stdint.h>

char *unicode_to_utf8 (uint32_t *in, unsigned int length);

unsigned char *to_utf_8 (unsigned char *in);

#endif
