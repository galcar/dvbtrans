
#include <stdlib.h>

#include <string.h>

#include "charset.h"


char *unicode_to_utf8 (uint32_t *in, unsigned int length) {

	int i;
	uint32_t u;

	int ut8_len = 0;

	char *utf8;
	char *out;

	if (in == NULL || length == 0) {
		return NULL;
	}

	for (i = 0; i < length; i++) {
		u = in[i];
		if (u <= 0x7f)
			ut8_len += 1;
		else if (u <= 0x07FF)
			ut8_len += 2;
		else if (u <= 0xFFFF)
			ut8_len += 3;
		else if (u <= 0x10FFFF)
			ut8_len += 4;
		else
			ut8_len += 3;
	}

	utf8 = (char *) malloc (ut8_len+1);

	out = utf8;

	for (i = 0; i < length; i++) {

		u = in[i];

		if (u <= 0x7f) {
			*out++ = (char) u;

		} else if (u <= 0x07FF) {
		    // 2-byte unicode
		    *out++ = (char) (((u >> 6) & 0x1F) | 0xC0);
		    *out++ = (char) (((u >> 0) & 0x3F) | 0x80);

		} else if (u <= 0xFFFF) {
		    // 3-byte unicode
			*out++ = (char) (((u >> 12) & 0x0F) | 0xE0);
			*out++ = (char) (((u >>  6) & 0x3F) | 0x80);
			*out++ = (char) (((u >>  0) & 0x3F) | 0x80);

		} else if (u <= 0x10FFFF) {
		    // 4-byte unicode
			*out++ = (char) (((u >> 18) & 0x07) | 0xF0);
			*out++ = (char) (((u >> 12) & 0x3F) | 0x80);
			*out++ = (char) (((u >>  6) & 0x3F) | 0x80);
			*out++ = (char) (((u >>  0) & 0x3F) | 0x80);

		} else {
		    // error - use replacement character
		    *out++ = (char) 0xEF;
		    *out++ = (char) 0xBF;
		    *out++ = (char) 0xBD;
		}
	}

	*out = '\0';

	return utf8;

}

unsigned char *to_utf_8 (unsigned char *in) {

	unsigned char *result = (unsigned char *) malloc (2*strlen(in));
	unsigned char *out = result;

	while (*in)
	    if (*in<128) *out++=*in++;
	    else *out++=0xc2+(*in>0xbf), *out++=(*in++&0x3f)+0x80;

	*out = '\0';

	return result;
}
