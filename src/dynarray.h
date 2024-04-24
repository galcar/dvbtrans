/*
	Dyn array version 1.0 - 11-3-2006
*/

#ifndef __DYNARRAY_H__
#define __DYNARRAY_H__

#include <stdlib.h>
#include <stdio.h>

typedef int (*dyn_comparator)(void *p1, void *p2);

typedef struct {
	int len; /* number of elements in p */
	void *p; /* the table of data */

	size_t data_size;

	dyn_comparator compare;
	
	void (*callback_free)(void *data);
	void (*callback_save)(void *data, FILE *f);
	void (*callback_load)(void *data, FILE *f);

} DYN_ARRAY;

DYN_ARRAY *dyn_array_new (size_t data_size);
void dyn_array_free (DYN_ARRAY *da);

void dyn_array_set_free_callback (DYN_ARRAY *da, void (*callback) (void *data));
void dyn_array_set_save_callback (DYN_ARRAY *da, void (*callback) (void *data, FILE *f));
void dyn_array_set_load_callback (DYN_ARRAY *da, void (*callback) (void *data, FILE *f));


int dyn_array_get_size (DYN_ARRAY *da);

void dyn_array_add (DYN_ARRAY *da, const void *data);
void *dyn_array_add_empty (DYN_ARRAY *da);

void *dyn_array_get_data (DYN_ARRAY *da, int pos);
void dyn_array_set_data (DYN_ARRAY *da, int pos, const void *data);

void dyn_array_remove (DYN_ARRAY *da, int pos);
void dyn_array_clear (DYN_ARRAY *da);

void dyn_array_set_comparator (DYN_ARRAY *da, dyn_comparator c);
int dyn_array_sub_quicksort (DYN_ARRAY *da, int first, int last);
int dyn_array_quicksort (DYN_ARRAY *da);

void dyn_array_load (DYN_ARRAY *da, FILE *f);
void dyn_array_save (DYN_ARRAY *da, FILE *f);

#endif
