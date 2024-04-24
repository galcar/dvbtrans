/*
	This program is a daemon that wakeup each minute and read the /etc/dvbprogd/dvbprogd.conf
file, searching for dvb record entries at the current time. If any, it starts the dvbrec
utility
compile:
gcc -I.. -o dvbprogd dvbprogd.c ../dynarray.o
*/
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <time.h>
#include <unistd.h>
#include <errno.h>

#include <sys/types.h>
#include <sys/wait.h>

#include "dynarray.h"

/* task record */
/* format :

start time;end time;status;dvbt://channel/program;dest_file

all times in date format: day/month/year hour:min
status can be W (waiting), R (recording), C (completed) or T (timed out)
channel is the number of channel
program the program number
title of the recording
dest_file the file to store data


*/

/* ------------------------------------ Other function section --------------- */

static void notify_desktop (const char *op, const char *info) {
	FILE *f;

	f = fopen ("/dev/pfifo", "w");
	fprintf (f, "rec %s %s\n", op, info);
	fclose (f);

}

/* ------------------------------------ Daemon Section ----------------------- */

/* termination flag */
static int _fin = 0;

/* a signal handler, for receiving the sign term */
void sig_term (int signum) {
	_fin = 1;
}

/* -----------------------------------
 * create a daemon and exit 
 * -----------------------------------
*/
static int daemonize () {

	FILE *f;
	pid_t pid;

	pid = fork ();

	switch(pid) {
        case -1:
			fprintf(stderr, "failed: fork: %s\n",strerror(errno));
			return -1;
        case 0:
			/* child */
			/* set the sigterm handler */
			signal(SIGTERM, sig_term);
			
			break;
        default:
			/* parent */
			/* save the pid */
			f = fopen ("/var/run/dvbprogd.pid", "w");
			if (f) {
				fprintf (f, "%d", pid);
				fclose (f);
			}

			exit(EXIT_SUCCESS);
	}

	setsid ();
	umask (0x022);

	chdir ("/");

	return 0;

}


/* ------------------------------------ Run Section ----------------------- */

static int __num_children = 0;

/* --------------------------
 * signal handler to find out when out child has exited
 * --------------------------
*/
void run_sigchld(int signum) {
	int status;
	pid_t hijo;

    hijo = wait(&status);

	if (WIFEXITED(status)) { // Normal termination
		fprintf (stderr, "EMENU: Process %d normal termination with code %d\n", hijo, 
			WEXITSTATUS (status));
	} else {
		fprintf (stderr, "EMENU: Process %d anormal termination\n", hijo);
	}

	// if there are still children waiting 
    // re-install the signal handler
    __num_children --;
    if (__num_children > 0) {
		// re-install the signal handler
		signal(SIGCHLD, run_sigchld);
	} 

	notify_desktop ("del", "terminated");
}

/* -----------------------------------
 * return the number of children currently running
 * -----------------------------------
*/
static int run_get_num_children () {
	return __num_children;
}

/* ----------------------------------- 
 * fork and exec a command
 * ----------------------------------- 
*/
static void run_execute(const char * command) {
	char * fixed_str;
	char ** args;
	int num_args;
	int curr_arg;
	int temp_len;
	int found_start;
	int pos;
	int r;
        
    // exit if nothing to execute;
    if (command == "") return;

		r = fork ();
        if (r == 0) {
                // im the child
                // i get to execute the command
		
                fixed_str = (char *) strdup(command);

                // find the number of arguments
                num_args = 0;
                found_start = 0;
                for (pos=0; pos<strlen(fixed_str); pos++) {
                        if ((!found_start) && (fixed_str[pos] != ' '))
                        {
                                found_start = 1;
                                num_args++;
                        }

                        if ((found_start) && (fixed_str[pos] == ' '))
                        {
                                found_start = 0;
                        }
                }
                // create the argument array
                args = malloc((num_args + 1) * sizeof(char *));
                found_start = 0;
                curr_arg = 0;
                temp_len = strlen(fixed_str);
                for (pos=0; pos<temp_len; pos++) {
                        if ((!found_start) && (fixed_str[pos] != ' '))
                        {
                                found_start = 1;
                                args[curr_arg] = &fixed_str[pos];
                                curr_arg++;
                        }

                        if ((found_start) && (fixed_str[pos] == ' '))
                        {
                                found_start = 0;
                                fixed_str[pos] = '\0';
                        }
                }
                args[curr_arg] = NULL;

                // call execvp
                execvp(args[0], args);
                
                // should never get here
                perror(args[0]);
                exit(100);
        } else if (r > 0) {

			// i'm the parent
			__num_children ++;
    	    signal(SIGCHLD, run_sigchld);

        	// i already have a signal handler to tell me when a child dies
        	// so I can just get on with my business
		}
}


/* ------------------------------------ Programming Section ------------------ */

typedef struct {
	long start;
	long end;
	char status;
	char *dvb;
	char *file;
} PROG;

/* ------------------------------------
	s_time format:
	day/month/year hour:minute
 * ------------------------------------
*/
static time_t parse_time (const char *s_time, int summer_time) {
	int day, mon, year, hour, min;
	struct tm t;
	time_t h = 0;
	
	day = mon = year = hour = min = 0;
	sscanf (s_time, "%d/%d/%d %d:%d", &day, &mon, &year, &hour, &min);

	t.tm_mday = day;
	t.tm_mon = mon - 1;
	t.tm_year = year - 1900;
	t.tm_hour = hour;
	t.tm_min = min;
	t.tm_sec = 0;
	t.tm_isdst = summer_time;
	
	h = mktime (&t);

	return h;
}

static char *format_time (time_t h) {
	struct tm *t;
	static char s[20];

	t = localtime (&h);

	sprintf (s, "%02d/%02d/%04d %02d:%02d", t->tm_mday, t->tm_mon + 1, t->tm_year + 1900, 
		t->tm_hour, t->tm_min);

	return s;

}



int write_prog_file (char *fn, DYN_ARRAY *p) {
	FILE *f;
	int i, len;
	PROG *prog;
	char *st, *et;

	if (p==NULL) {
		return -1;
	}

	f = fopen (fn, "w");
	if (!f) {
		return -1;
	}
	len = dyn_array_get_size (p);
	for (i=0; i < len; i++) {
		prog = dyn_array_get_data (p, i);
		st = strdup (format_time (prog->start));
		et = strdup (format_time (prog->end));
		fprintf (f, "%s;%s;%c;%s;%s\n", 
			st,
			et,
			prog->status,
			prog->dvb,
			prog->file);
		free (st);
		free (et);
	}

	fclose (f);

	return 0;
}

DYN_ARRAY *read_prog_file (char *fn, int summer_time) {
	FILE *f;
	DYN_ARRAY *p;
	char linea[1024];
	PROG prog;
	int n;
	char *token;

	f = fopen (fn, "r");
	if (!f) {
		return NULL;
	}

	p = dyn_array_new (sizeof(PROG));

	if (p==NULL) {
		fclose (f);
		return NULL;
	}	

	fgets (linea, sizeof(linea), f);
	while (!feof(f)) {
		/* trip the carriage return, if any */
		if (linea[strlen(linea)-1]=='\n') {
			linea[strlen(linea)-1]='\0';
		}
		n = 1;
		token = strtok (linea, ";");
		while (token != NULL) {
			switch (n) {
				case 1: /* first token, start time */
					prog.start = parse_time (token, summer_time);
					break;
				case 2: /* second token, end time */
					prog.end = parse_time (token, summer_time);
					break;
				case 3: /* status token */
					prog.status = token[0];
					break;
				case 4: /* dvb token */
					prog.dvb = strdup (token);
					break;
				case 5: /* stream dest token */
					prog.file = strdup (token);
					dyn_array_add (p, &prog);
					break;
			}
			n++;
			token = strtok (NULL, ";");
		}
		
		fgets (linea, sizeof(linea), f);
	}

	fclose (f);

	return p;
}

void prog_free (DYN_ARRAY *p) {
	int i, len;
	PROG *prog;

	if (p==NULL) {
		return;
	}

	len = dyn_array_get_size (p);
	for (i=0; i < len; i++) {
		prog = (PROG *) dyn_array_get_data (p, i);
		if (prog!=NULL) {
			free (prog->dvb);
			prog->dvb = NULL;
			free (prog->file);
			prog->file = NULL;
		}
	}

	dyn_array_free (p);

}

void check_prog (char *fn, time_t t, int horario_verano) {
	DYN_ARRAY *p;
	int len;
	PROG *prog;
	int i;
	int encontrado;
	char command[256];

	p = read_prog_file (fn, horario_verano);
	if (p==NULL) {
		return;
	}

	/* search the current program, if any */
	len = dyn_array_get_size (p);
	encontrado = 0;
	for (i=0; i < len && !encontrado; i++) {
		prog = (PROG *) dyn_array_get_data (p, i);
		if (prog->start == t && prog->status=='W') { /* time to start, and program Waiting */
			encontrado = 1;
		}
	}

	if (encontrado) {

		if (run_get_num_children()==0) { /* no currently recording */
			prog->status = 'R'; /* Recording */
			sprintf (command, "/usr/local/bin/dvbrec -d %d -o %s %s", 
				prog->end - prog->start, prog->file, prog->dvb);
			run_execute (command);
			
			notify_desktop ("add", prog->file);

		} else { /* cant start recording, because one is in progress */
			prog->status = 'P';	/* Passed */
		}

		write_prog_file (fn, p);
	}

	prog_free (p);
}

static time_t horalocal () { 
	time_t h;
	
	h = time (NULL);
	
	return h;

}

int main (int argc, char *argv[]) {
	struct timeval t;
	struct tm *hora;
	time_t h;
	int step;
	int r;

	if (daemonize () < 0) {
		exit (1);
	}

	/* the first time we must synchronize with the time at 0 seconds */
	h = horalocal ();
	hora = localtime (&h);

	step = 60 - hora->tm_sec;

	while (!_fin) {
		t.tv_sec  = step; /* one minute */
    	t.tv_usec = 0;

		r = select (0, NULL, NULL, NULL, &t);

		h += step;
		if (r==0) { /* time out */
			check_prog ("/etc/dvbprogd/dvbprogd.conf", h, hora->tm_isdst);
		}

		step = 60;
	}

	return 0;
}
