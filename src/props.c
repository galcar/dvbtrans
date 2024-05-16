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
#include <stdlib.h>

#include <stdio.h>

#include <string.h>

#include "props.h"

properties *properties_new () {

	properties *l = (properties *) malloc (sizeof (properties));

	l->len = 0;
	l->list = NULL;

	return l;
}

void properties_free (properties *p) {

	property *pv;
	int i;

	if (p == NULL) {
		return;
	}

	if (p->len > 0 && p->list != NULL) {
		for (i=0; i < p->len; i++) {
			pv = p->list[i];

			free (pv->key);
			pv->key = NULL;
			free (pv->value);
			pv->value = NULL;

			free (pv);
			p->list[i] = NULL;
		}

		free (p->list);
		p->list = NULL;
		p->len = 0;
	}

	free (p);

}

property *__properties_get_property (properties *p, const char *key) {
	property *pv;
	int i;

	if (p==NULL || key==NULL) {
		return NULL;
	}

	for (i=0; i < p->len; i++) {
		pv = p->list[i];

		if (strcmp (key, pv->key)==0) {
			return pv;
		}
	}

	return NULL;
}

void __properties_add (properties *p, property *pv) {

	if (p == NULL || pv == NULL) {
		return;
	}

	if(p->list == NULL) {
	    p->list = (property **) malloc(sizeof(property *));
	} else {
	    p->list = (property **) realloc(p->list, sizeof(property *) * (p->len + 1));
	}

	p->list[p->len] = pv;

	p->len ++;

}

void properties_add (properties *p, const char *key, const char *value) {
	property *current;

	if (p==NULL || key==NULL || value==NULL) {
		return;
	}

	// check if exists
	current = __properties_get_property (p, key);

	if (current != NULL) { // only replace the old value with the new one
		free (current->value);
		current->value = strdup (value);

	} else {

		property *pv = (property *) malloc (sizeof (property));

		pv->key = strdup (key);
		pv->value = strdup (value);

		__properties_add (p, pv);
	}
}

void properties_add_int (properties *p, const char *key, const int value) {
	char *s_value;
	int len;

	len = snprintf (NULL, 0, "%d", value);
	s_value = (char *) malloc (len+1);
	snprintf (s_value, len+1,"%d", value);

	properties_add (p, key, s_value);

	free (s_value);
}

void properties_add_long (properties *p, const char *key, const long value) {
	char *s_value;
	int len;

	len = snprintf (NULL, 0, "%ld", value);
	s_value = (char *) malloc (len+1);
	snprintf (s_value, len+1,"%d", value);

	properties_add (p, key, s_value);

	free (s_value);
}

properties *properties_load (const char *file_name) {

	char line[256], key[256], value[256];

	char *aux;

	char *k;

	int n;

	FILE *f;

	properties *p = NULL;

	f = fopen (file_name, "r");

	if (f == NULL) {
		return NULL;
	}

	p = properties_new ();

	while (fgets (line, sizeof(line), f) != NULL) {

		if (*line=='#') { // a comment
			continue;
		}

		aux = strstr (line, "=");

		if (aux==NULL) { /* ignore the line */
			continue;
		}

		/* read the left side (key) */

		k = line;

		n = 0;

		while (k != aux) {

			key[n++] = *k;

			k++;
		}
		key[n] = '\0';


		/* now read the right side (value) */

		k ++;

		n = 0;

		while (*k != '\0') {

			if (*k == '\r' || *k == '\n') { /* ignore it */

			} else {

				value[n++] = *k;
			}

			k++;
		}
		value[n] = '\0';

		properties_add (p, key, value);

	}

	fclose (f);

	return p;

}

int properties_size (properties *p) {
	if (p==NULL) {
		return 0;
	}
	return p->len;
}

property *properties_get_at (properties *p, int i) {
	if (p==NULL) {
		return NULL;
	}
	if (i < 0 || i >= p->len) {
		return NULL;
	}

	return p->list[i];
}

int properties_has_key (properties *p, const char *key) {
	int i;

	if (p==NULL || key==NULL) {
		return 0;
	}

	for (i=0; i < p->len; i++) {

		if (strcmp (key, p->list[i]->key)==0) {
			return 1;
		}
	}

	return 0;
}

char *properties_get (properties *p, const char *key) {

	property *pv;
	int i;

	if (p==NULL || key==NULL) {
		return NULL;
	}

	for (i=0; i < p->len; i++) {
		pv = p->list[i];

		if (strcmp (pv->key, key)==0) {
			return pv->value;
		}
	}

	return NULL;

}

char *properties_get_default (properties *p, const char *key, char *def) {

	char *v = properties_get (p, key);

	if (v == NULL) {
		return def;
	}

	return v;
}

int properties_get_int (properties *p, const char *key) {

	int v;

	char *aux;

	aux = properties_get (p, key);

	if (aux == NULL) {
		return 0;
	}

	return atoi (aux);

}

long properties_get_long (properties *p, const char *key) {

	long v;

	char *aux;

	aux = properties_get (p, key);

	if (aux == NULL) {
		return 0;
	}

	return atol (aux);

}

float properties_get_float (properties *p, const char *key) {

	int v;

	char *aux;

	aux = properties_get (p, key);

	if (aux == NULL) {
		return 0.0;
	}

	return strtof (aux, NULL);

}

double properties_get_double (properties *p, const char *key) {

	int v;

	char *aux;

	aux = properties_get (p, key);

	if (aux == NULL) {
		return 0.0;
	}

	return strtod (aux, NULL);

}
