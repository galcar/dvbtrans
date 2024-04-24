
#include <time.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <unistd.h>

#include "utils.h"

#include "recorder.h"

/* ------------------------------------
	return number of ms since epoch
	s_time format:
	day/month/year hour:minute
 * ------------------------------------
*/
long long _parse_time_ms (const char *s_time) {
	int day, mon, year, hour, min;
	struct tm t;
	time_t h = 0;

	day = mon = year = hour = min = 0;
	sscanf (s_time, "%d/%d/%d %d:%d", &day, &mon, &year, &hour, &min);

	memset(&t, 0, sizeof(struct tm));

	t.tm_mday = day;
	t.tm_mon = mon - 1;
	t.tm_year = year - 1900;
	t.tm_hour = hour;
	t.tm_min = min;
	t.tm_sec = 0;
	t.tm_isdst = -1;

	h = mktime (&t);

	return (long long) h * 1000;
}

char *_format_time (long long h_ms, char *s) {
	struct tm stime;

	time_t t_utc = h_ms / 1000;

	localtime_r(&t_utc, &stime);

	sprintf (s, "%02d/%02d/%04d %02d:%02d",
			stime.tm_mday, stime.tm_mon + 1, stime.tm_year + 1900,
			stime.tm_hour, stime.tm_min);

	return s;

}

void _prog_free_callback (void *data) {
	PROG *p = *((PROG **) data);

	prog_free (p);
}

/**
 * the program comparator used to create a list of ordered programs
 */
int _prog_comparator (void *p1, void *p2) {
	PROG *ip1 = *((PROG **) p1);
	PROG *ip2 = *((PROG **) p2);

	if ((ip1->status == 'W' || ip1->status == 'R') && (ip2->status != 'W' && ip2->status != 'R')) {
		return -1;
	}
	if ((ip2->status == 'W' || ip2->status == 'R') && (ip1->status != 'W' && ip1->status != 'R')) {
		return 1;
	}

	if (ip1->start == ip2->start) {
		return 0;
	} else if (ip1->start > ip2->start) {
		return 1;
	} else {
		return -1;
	}
}

RECORDER *recorder_new () {
	RECORDER *r = (RECORDER *) malloc (sizeof(RECORDER));

	r->storage = NULL;
	r->directory = NULL;

	r->id_counter = 1;

	r->progs = dyn_array_new (sizeof (PROG *));
	dyn_array_set_comparator (r->progs, _prog_comparator);

	dyn_array_set_free_callback (r->progs, _prog_free_callback);

	return r;
}

void recorder_free (RECORDER *r) {
	if (r == NULL) {
		return;
	}

	if (r->storage) {
		free (r->storage);
		r->storage = NULL;
	}
	if (r->directory) {
		free (r->directory);
		r->directory = NULL;
	}

	dyn_array_free (r->progs);

	free (r);
}

PROG *recorder_get_by_id (RECORDER *r, long id) {
	int i = 0;

	if (r == NULL) {
		return NULL;
	}

	for (i = 0; i < dyn_array_get_size (r->progs); i++) {
		PROG *prog = *((PROG **) dyn_array_get_data(r->progs, i));

		if (prog->id == id) {
			// found
			return prog;
		}
	}

	return NULL;
}

void recorder_add (RECORDER *r, PROG *p) {

	if (r == NULL || p == NULL) {
		return;
	}

	dyn_array_add (r->progs, &p);
	p->recorder = r;

	if (p->id == -1) {
		p->id = r->id_counter++;
	} else {
		if (p->id >= r->id_counter) {
			r->id_counter = p->id + 1;
		}
	}
}

int recorder_del_by_id (RECORDER *r, long id, int delete_file) {
	int i = 0;
	char fn[4096];

	if (r == NULL) {
		return 0;
	}

	for (i = 0; i < dyn_array_get_size (r->progs); i++) {
		PROG *prog = *((PROG **) dyn_array_get_data(r->progs, i));

		if (prog->id == id) {
			// found
			if (delete_file && prog_has_file (prog)) {
				//
				prog_get_file_path (prog, fn);
				remove (fn);
			}

			prog_free (prog);

			dyn_array_remove (r->progs, i);
			break;
		}
	}

	return 0;
}

int recorder_set_storage (RECORDER *recorder, const char *fn) {
	FILE *f;

	char linea[1024];
	PROG *prog;

	if (recorder == NULL || fn == NULL) {
		return -1;
	}

	recorder->storage = strdup (fn);

	f = fopen (fn, "r");
	if (!f) {
		return 0; // is not an error if file can't be open
	}

	long long t_now = current_timestamp_ms ();

	while (fgets(linea, sizeof(linea), f) != NULL) {
		/* trip the carriage return, if any */
		if (linea[strlen(linea)-1]=='\n') {
			linea[strlen(linea)-1]='\0';
		}

		if (linea[0] == '#') {
			continue;
		}

		prog = prog_parse (linea);
		if (prog == NULL) {
			continue;
		}

		prog->recorder = recorder;

		if (prog->status == 'R') {
			prog->status = 'W';
		}

		if (prog->status == 'W' && prog->end < t_now) {
			prog->status = 'T'; // timed out

		} else if (prog->status == 'C') {
			// check if file exists
			if (!prog_has_file (prog)) {
				// ignore it
				//continue;
			}
		}

		recorder_add (recorder, prog);

	}

	fclose (f);

	// reorder
	recorder_sort (recorder);

	return 0;
}

int recorder_save (RECORDER *r) {
	FILE *f;
	int i, len;
	PROG *prog;
	char st[20], et[20];

	if (r==NULL || r->storage == NULL) {
		return -1;
	}

	f = fopen (r->storage, "w");
	if (!f) {
		return -1;
	}

	len = dyn_array_get_size (r->progs);

	for (i=0; i < len; i++) {
		PROG *prog = *((PROG **) dyn_array_get_data(r->progs, i));

		_format_time (prog->start, st);
		_format_time (prog->end, et);

		fprintf (f, "%ld;%s;%s;%c;dvbt://%d/%d;%s;%s\n",
			prog->id,
			st,
			et,
			prog->status,
			prog->channel,
			prog->service,
			prog->title,
			prog->file);

	}

	fclose (f);

	return 0;
}

void recorder_sort (RECORDER *r) {
	if (r == NULL) {
		return;
	}

	dyn_array_quicksort (r->progs);
}

PROG * prog_new () {
	PROG *prog = (PROG *) malloc (sizeof (PROG));

	prog->recorder	= NULL;
	prog->id		= -1;
	prog->start 	= 0;
	prog->end 		= 0;
	prog->status 	= '\0';
	prog->channel	= 0;
	prog->service	= 0;
	prog->title		= NULL;
	prog->file 		= NULL;

	prog->out		= NULL;

	return prog;
}

/**
 * a prog line: start;end;status;dvbt://channel/program;filename
 */
PROG *prog_parse (char *line) {

	PROG *prog = NULL;

	int n;
	char *token;

	prog = prog_new();

	n = 1;
	token = strtok (line, ";");
	while (token != NULL) {

		switch (n) {
			case 1:
				prog->id = atol (token);
				break;
			case 2: /* first token, start time */
				prog->start = _parse_time_ms (token);
				break;
			case 3: /* second token, end time */
				prog->end = _parse_time_ms (token);
				break;
			case 4: /* status token */
				prog->status = token[0];
				break;
			case 5: /* dvb token */
				sscanf (token, "dvbt://%d/%d", &prog->channel, &prog->service);
				break;
			case 6: /* title */
				prog->title = strdup (token);
				break;
			case 7: /* stream dest token */
				prog->file = strdup (token);
				break;
		}
		n++;
		token = strtok (NULL, ";");
	}

	return prog;
}

void prog_free (PROG *prog) {
	if (prog == NULL) {
		return;
	}

	if (prog->title) {
		free (prog->title);
		prog->title = NULL;
	}

	if (prog->file) {
		free (prog->file);
		prog->file = NULL;
	}

	prog->out = NULL;

	free (prog);
}

int prog_get_file_path (PROG *prog, char *path) {

	if (prog == NULL || prog->recorder == NULL) {
		return -1;
	}

	sprintf (path, "%s/%s", prog->recorder->directory, prog->file);

	return 0;
}

int prog_has_file (PROG *prog) {

	char path[4096];

	if (prog_get_file_path (prog, path) == -1) {
		return 0;
	}

	if (access(path, F_OK) == 0) { // file exists
		return 1;
	}

	return 0;

}



void recorder_log (RECORDER *r) {
	int i;

	for (i = 0; i < dyn_array_get_size (r->progs); i++) {

		PROG *p = *((PROG **) dyn_array_get_data(r->progs, i));
		printf ("Record %d %ld, %lld, %lld %c dvbt://%d/%d %s %s\n", i
				, p->id
				, p->start
				, p->end
				, p->status
				, p->channel
				, p->service
				, p->title
				, p->file
				);
	}
}
