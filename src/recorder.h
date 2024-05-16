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
#ifndef __RECORDER_H__
#define __RECORDER_H__

typedef struct _prog PROG;
typedef struct _recorder RECORDER;

#include "dynarray.h"

#include "dvbtrans.h"

struct _prog {
	RECORDER 			*recorder;

	long 				id;
	long long 			start;
	long long 			end;
	char 				status; // W (waiting), R (recording), C (completed), T (timed out), D (disable)
	mydvb_tuner_type_t 	type;
	int 				channel;
	int 				service;
	char 				*title;
	char 				*file;

	STREAM_OUTPUT 		*out;
};

struct _recorder {

	char *storage;

	char *directory; // base path where records are stored

	long id_counter;

	DYN_ARRAY *progs;

};

RECORDER *recorder_new ();
void recorder_free (RECORDER *r);

PROG *recorder_get_by_id (RECORDER *r, long id);

void recorder_add (RECORDER *r, PROG *p);

int recorder_del_by_id (RECORDER *r, long id, int delete_file);

int recorder_set_storage (RECORDER *recorder, const char *fn);

int recorder_save (RECORDER *r);

void recorder_sort (RECORDER *r);

PROG *prog_new ();

PROG *prog_parse (char *line);

void prog_free (PROG *prog);

int prog_get_file_path (PROG *prog, char *path);

int prog_has_file (PROG *prog);

long long parse_time_ms (const char *s_time);

void recorder_log (RECORDER *r);

#endif
