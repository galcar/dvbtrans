#ifndef __RECORDER_H__
#define __RECORDER_H__

typedef struct _prog PROG;
typedef struct _recorder RECORDER;

#include "dynarray.h"

#include "dvbtrans.h"

struct _prog {
	RECORDER *recorder;

	long id;
	long long start;
	long long end;
	char status; // W (waiting), R (recording), C (completed), T (timed out), D (disable)
	int channel;
	int service;
	char *title;
	char *file;

	STREAM_OUTPUT *out;
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
