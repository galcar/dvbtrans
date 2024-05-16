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
/*
	Dyn array version 1.0 - 11-3-2006
*/

#include <stdlib.h>
#include <string.h>

#include <dynarray.h>

DYN_ARRAY *dyn_array_new (size_t data_size) {
	DYN_ARRAY *da;

	da = (DYN_ARRAY *) malloc (sizeof (DYN_ARRAY));
	da->len = 0;
	da->p   = NULL;
	da->data_size = data_size;
	da->compare = NULL;
	da->callback_free = NULL;
	da->callback_save = NULL;
	da->callback_load = NULL;

	return da;
}

void dyn_array_free (DYN_ARRAY *da) {
	void *p;
	int i;

	if (da==NULL) {
		return;
	}

	dyn_array_clear (da);
	
	da->data_size = 0;

	free (da);
}

void dyn_array_set_free_callback (DYN_ARRAY *da, void (*callback) (void *data)) {
	if (da==NULL) {
		return;
	}

	da->callback_free = callback;
}

void dyn_array_set_save_callback (DYN_ARRAY *da, void (*callback) (void *data, FILE *f)) {
	if (da==NULL) {
		return;
	}

	da->callback_save = callback;
}

void dyn_array_set_load_callback (DYN_ARRAY *da, void (*callback) (void *data, FILE *f)) {
	if (da==NULL) {
		return;
	}

	da->callback_load = callback;
}


int dyn_array_get_size (DYN_ARRAY *da) {
	if (da==NULL) {
		return 0;
	}

	return da->len;
}

void dyn_array_add (DYN_ARRAY *da, const void *data) {
	void *p;
	da->len ++;
	if (da->p == NULL) {
		da->p = malloc (da->data_size);
	} else {
		da->p = realloc (da->p, da->data_size * da->len);
	}
	p = da->p + da->data_size * (da->len - 1);
	memcpy (p, data, da->data_size);
}

void *dyn_array_add_empty (DYN_ARRAY *da) {
	void *p;
	da->len ++;
	if (da->p == NULL) {
		da->p = malloc (da->data_size);
	} else {
		da->p = realloc (da->p, da->data_size * da->len);
	}
	p = da->p + da->data_size * (da->len - 1);

	/* initialize the reserved area to 0 values */
	memset (p, 0, da->data_size);

	return p;
}


void *dyn_array_get_data (DYN_ARRAY *da, int pos) {
	void *p;
	if (da == NULL) {
		return NULL;
	}

	if (pos < 0 || pos >= da->len) {
		return NULL;
	}
	p = da->p + pos * da->data_size;

	return p;
}

void dyn_array_set_data (DYN_ARRAY *da, int pos, const void *data) {
	void *p;

	if (da==NULL || data==NULL) {
		return;
	}
	if (pos < 0 || pos >= da->len) {
		return;
	}
	p = da->p + pos * da->data_size;
	memcpy (p, data, da->data_size);
}

void dyn_array_remove (DYN_ARRAY *da, int pos) {
	void *p, *p_next;
	int len;

	if (da == NULL) {
		return;	
	}

	if (pos < 0 || pos >= da->len) {
		return;
	}

	/* first, reallocate all elements from pos to end */
	len = (da->len-1 - pos) * da->data_size;
	p = da->p + pos * da->data_size;
	p_next = da->p + (pos+1) * da->data_size;
	if (len > 0) {
		memmove (p, p_next, len);
	}

	/* second reallocate memory (or free) */
	da->len --;
	da->p = realloc (da->p, da->data_size * da->len);
}

void dyn_array_clear (DYN_ARRAY *da) {
	void *p;
	int i;

	if (da==NULL) {
		return;
	}

	if (da->p) {

		if (da->callback_free!=NULL) {
			/* itera sobre los elementos para liberarlos */
			for (i=0; i < da->len; i++) {
				p = da->p + i * da->data_size;
				da->callback_free (p);
			}
		}

		free (da->p);
		da->p=NULL;
		da->len = 0;
	}
}

int _dyn_quicksort_partition(DYN_ARRAY *da, int f, int l) {
    int up,down;

	void *piv;
	void *y_up, *y_down;
	void *temp;

	piv = malloc (da->data_size);
	memcpy (piv, dyn_array_get_data (da, f), da->data_size);

    up = f;
    down = l;
    do { 
		y_up = dyn_array_get_data (da, up);
        while (da->compare(y_up, piv) <= 0 && up < l) {
            up++;
			y_up = dyn_array_get_data (da, up);
        }
		y_down = dyn_array_get_data (da, down);
        while (da->compare(y_down,piv) >= 1) {
            down--;
			y_down = dyn_array_get_data (da, down);
        }
        if (up < down ) {
            /* temp = y[up]; */
			temp = malloc (da->data_size);
			memcpy (temp, dyn_array_get_data (da, up), da->data_size); 
            /* y[up] = y[down]; */
			y_down = dyn_array_get_data (da, down);
			dyn_array_set_data (da, up, y_down);
			/* y[down] = temp; */
			dyn_array_set_data (da, down, temp);
			free (temp);
			temp = NULL;
        }
    } while (down > up);
    /*y[f] = y[down];*/
	y_down = dyn_array_get_data (da, down);
	dyn_array_set_data (da, f, y_down);
	
    /* y[down] = piv; */
	dyn_array_set_data (da, down, piv);
	free (piv);

    return down;
}

void dyn_array_set_comparator (DYN_ARRAY *da, dyn_comparator c) {
	if (da==NULL || c==NULL) {
		return;
	}

	da->compare = c;
}

/* yea, a quicksort, remember, after quicksort, next adds will not be sort*/
int dyn_array_sub_quicksort (DYN_ARRAY *da, int first, int last) {
    int pivIndex = 0;
	
	if (da->compare==NULL) {
		return -1;
	}

    if(first < last) {
        pivIndex = _dyn_quicksort_partition (da, first, last);
        dyn_array_sub_quicksort (da, first, (pivIndex-1));
        dyn_array_sub_quicksort (da, (pivIndex+1), last);
    }
	return 0;
}

int dyn_array_quicksort (DYN_ARRAY *da) {

	return dyn_array_sub_quicksort (da, 0, da->len-1);

}

void dyn_array_load (DYN_ARRAY *da, FILE *f) {
	int len;
	int i;
	void *p;

	if (da == NULL || f == NULL) {
		return;
	}

	if (da->p == NULL || da->callback_load == NULL) {
		return;
	}

	fread (&len, sizeof(int), 1, f);
	if (len > 0) {

		for (i=0; i < len; i++) {
			p = dyn_array_add_empty (da);
			da->callback_load (p, f);
		}
	}

}

void dyn_array_save (DYN_ARRAY *da, FILE *f) {
	int i;
	void *p;

	if (da == NULL || f == NULL) {
		return;
	}

	if (da->p == NULL || da->callback_save == NULL) {
		return;
	}

	fwrite (&da->len, sizeof(int), 1, f);

	/* itera sobre los elementos para guardarlos */
	for (i=0; i < da->len; i++) {
		p = da->p + i * da->data_size;
		da->callback_save (p, f);
	}

}

/* 
 * how to use: 
int main (int argc, char *argv[]) {
	DYN_ARRAY *da;
	char *s;
	int i;

	da = dyn_array_new (13);
	dyn_array_add (da, "hola a todos");

	for (i=0; i < dyn_array_get_size (da); i++) {
		s = (char *) dyn_array_get_data (da, i);
		if (s) {
			printf ("Valor de s: %s\n", s);
		}
	}

	dyn_array_free (da);
}
*/
