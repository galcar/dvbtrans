#ifndef __PROPS_H__
#define __PROPS_H__

typedef struct {

	char *key;

	char *value;

} property;

typedef struct {

	int len;

	property **list;

} properties;

properties *properties_new ();
void properties_free (properties *p);

void properties_add (properties *p, const char *key, const char *value);
void properties_add_int (properties *p, const char *key, const int value);
void properties_add_long (properties *p, const char *key, const long value);

properties *properties_load (const char *file_name);

int properties_size (properties *p);

int properties_has_key (properties *p, const char *key);

property *properties_get_at (properties *p, int i);

char *properties_get (properties *p, const char *key);

char *properties_get_default (properties *p, const char *key, char *def);

int properties_get_int (properties *p, const char *key);

long properties_get_long (properties *p, const char *key);

float properties_get_float (properties *p, const char *key);

double properties_get_double (properties *p, const char *key);

#endif
