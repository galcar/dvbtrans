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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

#include <signal.h>

#include <sys/stat.h>

#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <arpa/inet.h>


#include <unistd.h>
#include <getopt.h>
extern char *optarg;
extern int optind, opterr, optopt;

#include <mydvb.h>
#include <mydvb_log.h>

#include <mydvb_descriptors.h>

#include <mydvb_date.h>

#include "nettools.h"

#include "tcpterm.h"

#include "http_server.h"

#include "props.h"
#include "dynarray.h"

#include "utils.h"

#include "dvbviewer.h"

#include "dvbtrans.h"

static APP_INFO app_info;
long total_bytes = 0;




void save_pid (const char *pid_file, pid_t pid) {
	FILE *f;

	if (pid_file == NULL) {
		return;
	}

	f = fopen (pid_file, "w");

	if (f) {

		fprintf (f, "%d", pid);

		fclose (f);
	}
}

/**
 * Run this program as a daemon
 */
void daemonize (const char *pid_file) {

	pid_t pid, sid;

	pid = fork ();

	if (pid < 0) {

		exit(EXIT_FAILURE);
	}

	if ( pid > 0) {

		/* save the pid */
		save_pid (pid_file, pid);

		exit (EXIT_SUCCESS);
	}

	/* umask */
	umask (0);

	/* sid */
	sid = setsid ();
	if (sid < 0) {
		exit (EXIT_FAILURE);
	}

	/* chdir */
	if ((chdir ("/")) < 0) {

		exit (EXIT_FAILURE);
	}

	/* Close out the standard file descriptors */
	/*
            close(STDIN_FILENO);
            close(STDOUT_FILENO);
           close(STDERR_FILENO);
	 */

}

/**
 * A signal handler for terminating the process
 */
void sig_term (int v) {

	mydvb_end_main_loop (&app_info.engine);

}

MYDVB_TUNE *tuner_program (MYDVB_ENGINE *engine, INFO_PROGRAM *ip) {
	MYDVB_TUNE *tuner;

	tuner = mydvb_tuner_channel (engine, ip->channel);

	if (tuner == NULL) {
		return NULL;
	}

	if (tuner->data != NULL) {
		INFO_PROGRAM *current = (INFO_PROGRAM *) tuner->data;

		if (current->n != ip->n) {
			mydvb_tuner_release (engine, tuner);
			return NULL; // no available
		}
	}

	tuner->data = ip;

	return tuner;
}

int send_broadcast (int sockfd, unsigned char *buf, int buf_len, struct sockaddr_in *target) {

	int v = 0;

	v = sendto(sockfd, buf, buf_len, 0,
		(struct sockaddr*) target, sizeof(struct sockaddr));

	if (v == -1) {
		mydvb_log (MYDVB_LOG_LEVEL_ERROR, "Failed to send network data packet: %s", strerror(errno));
	} 

	return v;
}



int net_set_target (NET_OUTPUT *no, const char *net_host, int net_port) {

	char ip[128];

	if (get_ip_by_host (net_host, ip)==NULL) {
		return -1;
	}

	bzero((unsigned char *) &no->target, sizeof(no->target));
	no->target.sin_family=AF_INET;
	no->target.sin_port=htons(net_port);
	//no->target.sin_addr.s_addr=inet_addr(ip);
	if (inet_aton (ip, &no->target.sin_addr) == 0) {
		return -1;
	}

	return 0;
}

STREAM_OUTPUT *open_net_output (const char *net_host, int net_port) {

	STREAM_OUTPUT *so = (STREAM_OUTPUT *) malloc (sizeof(STREAM_OUTPUT));

	if (net_set_target (&so->u.net_output, net_host, net_port) == -1) {
		free (so);
		return NULL;
	}

	if((so->u.net_output.sockfd=socket(AF_INET,SOCK_DGRAM,IPPROTO_UDP))==-1) {
		free (so);
		mydvb_log (MYDVB_LOG_LEVEL_ERROR, "Failed to create the network transmission socket");

		return NULL;

	}

	so->type = OUTPUT_TYPE_NET;

	return so;

}

/* 
  return a copy of the full path name. You should free the return value
*/
static char *get_file_path (const char *fname) {
        char *p=NULL, *aux=NULL;

        if (fname == NULL) {
                return NULL;
        }

        aux = strdup (fname);
        p = strrchr (aux, '/');
        if (p!=NULL) {
                *p = '\0';
        } else {
                free (aux);
                aux = NULL;
        }
        return aux;
}

STREAM_OUTPUT *open_file_output (const char *file_name) {
	struct stat attrs;
	char d_path[256];
	char *s;

	STREAM_OUTPUT *fileout = NULL;

	/* comprueba que el fichero se puede crear y manipular */
	/* a. obtiene el directorio donde se va a guardar el fichero */
	s = get_file_path (file_name);
	if (s==NULL) { /* no path found */
		sprintf (d_path, "%s/", getenv("PWD"));
	} else {
		if (file_name[0]=='/') { /* absolute path */
			sprintf (d_path, "%s/", s);
		} else { /* relative path */
			sprintf (d_path, "%s/%s/", getenv("PWD"), s);
		}
		free (s);
	}


	/* b. del directorio obtenemos sus atributos */
	if (stat (d_path, &attrs)==0) {
		/* c. examina los permisos sobre el directorios */
		if ((attrs.st_mode & S_IWUSR)==0 && 
			(attrs.st_mode & S_IWGRP)==0 &&
			(attrs.st_mode & S_IWOTH)==0 ) { /* al menos alguien debe poder escribir */
			return NULL;
		}
	} else {
		/* exit */
		return NULL;
	}

	fileout = (STREAM_OUTPUT *) malloc (sizeof (STREAM_OUTPUT));

	fileout->u.file_output.f = fopen (file_name, "w+b");
	if (!fileout->u.file_output.f) {
		free (fileout);
		return NULL;
	}

	fileout->type = OUTPUT_TYPE_FILE;

	return fileout;
}

void stream_output_close (STREAM_OUTPUT *so) {
	HTTP_RESPONSE *response;

	if (so==NULL) {
		return;
	}

	switch (so->type) {
		case OUTPUT_TYPE_NET: 
			if (so->u.net_output.sockfd!=-1) {
				close (so->u.net_output.sockfd);
				so->u.net_output.sockfd = -1;
			}
			break;
		case OUTPUT_TYPE_FILE:
			if (so->u.file_output.f != NULL) {
				fclose (so->u.file_output.f);
				so->u.file_output.f = NULL;
			}
			break;

		case OUTPUT_TYPE_HTTP:
			response = so->u.http_output.response;
			http_server_request_free (response->request);
			http_server_response_free (response);

			break;

		case OUTPUT_TYPE_RECORD:
			response = so->u.record_output.response;
			http_server_request_free (response->request);
			http_server_response_free (response);

			if (so->u.record_output.f != NULL) {
				fclose (so->u.record_output.f);
				so->u.record_output.f = NULL;
			}

			break;
	}

	free (so);
}

int stream_output_send (STREAM_OUTPUT *so, unsigned char *buf, int len) {

	int n = -1;
	HTTP_RESPONSE *receiver;

	if (so==NULL) {
		return -1; // invalid object
	}

	switch (so->type) {
		case OUTPUT_TYPE_NET:

			n = send_broadcast (so->u.net_output.sockfd, buf, len, &so->u.net_output.target);
			break;

		case OUTPUT_TYPE_FILE:

			if (so->u.file_output.f != NULL) {

				n = len * fwrite (buf, len, 1, so->u.file_output.f);

				if (ferror (so->u.file_output.f)) {
					mydvb_log (MYDVB_LOG_LEVEL_ERROR, "Error writing to file %s", strerror (errno));
					n = -1;
				}

			} else {
				n = -1;
			}
			break;

		case OUTPUT_TYPE_HTTP:
			receiver = so->u.http_output.response;

			n = http_server_send_chunked (receiver, buf,  len);
			if (n < 0) {
				mydvb_log (MYDVB_LOG_LEVEL_ERROR, "Http Streaming error: %s", strerror (errno));
			}
			break;

		case OUTPUT_TYPE_RECORD:
			receiver = so->u.record_output.response;

			n = http_server_send_chunked (receiver, buf,  len);
			if (n < 0) {
				mydvb_log (MYDVB_LOG_LEVEL_ERROR, "Http Streaming error: %s", strerror (errno));
			}
			break;
	}

	return n;
}

void _free_stream_output (void *p) {
	if (p==NULL) {
		return;
	}

	STREAM_OUTPUT *so = *((STREAM_OUTPUT **) p);

	stream_output_close (so);

}

void cmd_help (TCP_CLIENT *client) {
	tcp_client_write_ln (client, "Commands: help, tuners, engine, broadcast, stop, channels, broadcast, scan, show, epg, exit, shutdown");
	tcp_client_write_ln (client, "\thelp: show this");
	tcp_client_write_ln (client, "\tengine: show core engine current state");
	tcp_client_write_ln (client, "\tclients: list connected clients");
	tcp_client_write_ln (client, "\ttuners: list all tuners in the systems and its current state");
	tcp_client_write_ln (client, "\tchannels: list currrent available channels");
	tcp_client_write_ln (client, "\tmove <a> <b>: move channel number from a to b");
	tcp_client_write_ln (client, "\tbroadcast <number> <target> <port>: start broadcast of service number to host target and port");
	tcp_client_write_ln (client, "\tscan start: start a new channels scan");
	tcp_client_write_ln (client, "\tscan cancel: cancel current channels scan, don't save any result");
	tcp_client_write_ln (client, "\tscan stop: stop current channels scan and save the result in the channels file");
	tcp_client_write_ln (client, "\tscan status: show status of current channels scan");
	tcp_client_write_ln (client, "\texit: exit and close the current terminal");
	tcp_client_write_ln (client, "\tshutdown: shutdown dvb transmitter");
}

void cmd_clients (APP_INFO *app, TCP_CLIENT *client) {

	if (app->http == NULL) {
		tcp_client_write_ln (client, "No http server running");
	} else {
		for (int i = 0; i < dyn_array_get_size(app->http->clients); i++) {
			HTTP_CLIENT *c = *((HTTP_CLIENT **) dyn_array_get_data (app->http->clients, i));

			tcp_client_write_ln (client, "Http client %s at port %d"
				,c->ip
				,c->dst_port
			);
		}
	}

	if (app->server == NULL) {
		tcp_client_write_ln (client, "No terminal server running");
	} else {
		for (int i = 0; i < app->server->clients_len; i++) {
			TCP_CLIENT *t = app->server->clients[i];

			tcp_client_write_ln (client, "Terminal client %s at port %d"
				,t->ip
				,t->dst_port
			);

		}
	}

}

static char *_cmd_tabs[] = {
		""
		,"\t"
		,"\t\t"
		,"\t\t\t"
		,"\t\t\t\t"
		,"\t\t\t\t\t"
		,"\t\t\t\t\t\t"
};

void _cmd_descriptors (TCP_CLIENT *client, DYN_ARRAY *descriptors, int num_tabs) {

	char *utf8 = NULL;

	for (int i = 0; i < dyn_array_get_size (descriptors); i++) {

		mydvb_descriptor *d = (mydvb_descriptor *) dyn_array_get_data (descriptors, i);

		tcp_client_write_ln (client, "%sDescriptor type %X (%s), table %X"
				,_cmd_tabs[num_tabs]
				,d->info.type
				,mydvb_descriptor_type_table()[d->info.type]
				,d->info.table
				);

		if (d->info.type == 0x0A) {

			for (int j=0; j < d->iso639_lang.num_langs; j++) {
				tcp_client_write_ln (client, "%sLang %s %d"
					, _cmd_tabs[num_tabs]
					,d->iso639_lang.langs[j].lang
					,d->iso639_lang.langs[j].audio_type
					);
			}

		} else if (d->info.type == 0x40) {
			utf8 = mydvb_text_to_utf8 (d->network_name.name);
			tcp_client_write_ln (client, "%sNetwork name: %s"
				, _cmd_tabs[num_tabs]
				, utf8
				);
			if (utf8) {
				free (utf8);
			}
		}
	}
}

void cmd_engine (APP_INFO *app, TCP_CLIENT *client) {
	MYDVB_ENGINE *engine = &app->engine;

	tcp_client_write_ln (client, "Engine state: Running: %d; Listeners: %d; Tuners: %d; Channels: %d; Poll length: %d"
			,engine->mainloop
			,dyn_array_get_size (engine->listeners)
			,dyn_array_get_size (engine->tuners)
			,dyn_array_get_size (engine->channels)
			,engine->poll_len
	);

	for (int i = 0; i < dyn_array_get_size (engine->channels); i++) {
		MYDVB *mydvb = *((MYDVB **) dyn_array_get_data (engine->channels, i));

		tcp_client_write_ln (client, "\tChannel %d %s - Ready: %d",mydvb->channel,mydvb_tuner_type_table()[mydvb->type],mydvb->ready);
		if (mydvb->pat) {
			tcp_client_write_ln (client, "\t\tPAT: ver %d, TS_ID %d, Section %d, SectionNext %d"
					,mydvb->pat->version
					,mydvb->pat->ts_id
					,mydvb->pat->section_n
					,mydvb->pat->section_n_l
			);

			if (mydvb->pat->nit) {
				tcp_client_write_ln (client, "\t\tNIT: %d, PID: %d"
						,mydvb->pat->nit->network_id
						,mydvb->pat->nit->pid
				);
				_cmd_descriptors (client, mydvb->pat->nit->descriptors, 3);
			}

			for (int j=0; j < dyn_array_get_size (mydvb->pat->programs); j++) {
				MYDVB_PROGRAM *p = (MYDVB_PROGRAM *) dyn_array_get_data (mydvb->pat->programs, j);

				tcp_client_write_ln (client, "\t\tPROGRAM %d, PID: %d, ver: %d, PCR PID: %d"
						,p->number
						,p->pmt_pid
						,p->version
						,p->pcr_pid
						);
				_cmd_descriptors (client, p->descriptors, 3);

				for (int k=0; k < dyn_array_get_size (p->streams); k++) {

					MYDVB_STREAM *stream = (MYDVB_STREAM *) dyn_array_get_data (p->streams, k);

					tcp_client_write_ln (client, "\t\t\tStream type %X (%s), PID: %d"
							,stream->type
							,mydvb_stream_type_table()[stream->type]
							,stream->pid
							);
					_cmd_descriptors (client, stream->descriptors,4);
				}
			}
		}
	}
}

void cmd_tuners (APP_INFO *app, TCP_CLIENT *client) {

	for (int i = 0; i < dyn_array_get_size (app->engine.tuners); i++) {
		MYDVB_TUNE *tuner = *((MYDVB_TUNE **) dyn_array_get_data(app->engine.tuners,i));

		mydvb_tune_get_info (tuner);

		tcp_client_write_ln (client, "Tuner %d, %s at (%d-%d-%d) of type %d (%s). Fmin: %d, Fmax: %d, Fstep %d. Caps: %lX. Refs: %d; Status %d; frequency: %d; strength: %4.6f; snr: %4.6f; ber: %4.6f"
						, i
						, tuner->name
						, tuner->device, tuner->adapter, tuner->demuxer
						, tuner->type, mydvb_tuner_type_table()[tuner->type]
						, tuner->freq_min
						, tuner->freq_max
						, tuner->freq_step_min
						, tuner->caps
						, tuner->references
						, tuner->status
						, tuner->p.frequency
						, tuner->info.signal
						, tuner->info.snr
						, tuner->info.ber
						);
	}
}

void cmd_channels (INFO_DVB *dvb, TCP_CLIENT *client) {

	int i, j, k;

	INFO_CHANNEL *ichannel = NULL;
	INFO_PROGRAM *iprogram = NULL;
	INFO_STREAM *istream = NULL;

	struct dvb_frontend_parameters *p;

	char *provider = NULL;
	char *service  = NULL;

	for (i=0; i < dvb->channels_len; i++) {
		ichannel = dvb->channels[i];

		if (ichannel!=NULL) {
			p = &ichannel->p;

			for (j=0; j < ichannel->programs_len; j++) {
				iprogram = ichannel->programs[j];

				if (iprogram!=NULL) {
					provider = mydvb_text_to_utf8 (iprogram->provider);
					service  = mydvb_text_to_utf8 (iprogram->service);
					tcp_client_write_ln (client, "%d;%s %d/%d;%s;%s;%d (%s);%d",
							iprogram->user_number,
							mydvb_tuner_type_table()[ichannel->type],
							mydvb_tune_get_uhf_channel (p->frequency),
							iprogram->n,
							(unsigned char *) (provider==NULL ? EMPTY_STRING : provider),
							(unsigned char *) (service ==NULL ? EMPTY_STRING : service),
							iprogram->type, mydvb_service_type_table()[iprogram->type],
							iprogram->scrambled
							);
					if (provider) free (provider);
					if (service) free (service);
				}
			}
		}
	}

}

void _show_eit_entry (TCP_CLIENT *client, int base_code, MYDVB_EIT *eit) {

	DYN_ARRAY *entries;
	int len, i, j;

	MYDVB_EIT_ENTRY *eit_entry = NULL;
	mydvb_short_event_descriptor *sed;
	mydvb_extended_event_descriptor *eed;
	mydvb_content_descriptor *cd;

	mydvb_ext_event_item *eei;

	char *text = NULL;
	char *text2 = NULL;

	struct tm stime;

	if (eit == NULL) {
		return;
	}

	entries = eit->entries;

	if (entries == NULL) {
		return;
	}

	len = dyn_array_get_size (entries);
	for (i = 0; i < len; i++) {
		eit_entry = (MYDVB_EIT_ENTRY *) dyn_array_get_data (entries, i);

		time_t t_utc = mydvb_date_to_tm (eit_entry->start_time, &stime);

		localtime_r(&t_utc, &stime);

		tcp_client_write_ln (client, "%d;%d;%d/%d/%d %d:%d:%d;%d;%s;%d-%d,%d,%s",
			base_code,
			eit_entry->event_id,
			stime.tm_year + 1900,
			stime.tm_mon + 1,
			stime.tm_mday,
			stime.tm_hour,
			stime.tm_min,
			stime.tm_sec, 	/* date of start */
			eit_entry->duration,			/* in seconds */
			mydvb_running_status_table()[eit_entry->running_status],
			eit_entry->scram
			,stime.tm_isdst
            ,stime.tm_gmtoff
            ,stime.tm_zone);

		sed = (mydvb_short_event_descriptor * )
					mydvb_descriptor_find (eit_entry->descriptors, 0x4d);
		if (sed != NULL) {
			text = mydvb_text_to_utf8 (sed->event_name);
			text2 = mydvb_text_to_utf8 (sed->text);
			tcp_client_write_ln (client, "%d;%s;%s",
					base_code+1,
					text, // sed->event_name->text,
					text2 // sed->text->text
					);
			if (text2 != NULL) free (text2);
			if (text != NULL) free (text);
		}

		eed = (mydvb_extended_event_descriptor *)
					mydvb_descriptor_find (eit_entry->descriptors, 0x4e);
		if (eed != NULL) {

			for (j=0; j < dyn_array_get_size (eed->items); j++) {
				eei = (mydvb_ext_event_item *) dyn_array_get_data (eed->items, j);

				text = mydvb_text_to_utf8 (eei->item_description);
				text2 = mydvb_text_to_utf8 (eei->item_value);

				tcp_client_write_ln (client, "%d;%s;%s",
												base_code+2,
												text, text2
												);

				if (text) free (text);
				if (text2) free (text2);
			}

			text = mydvb_text_to_utf8 (eed->text);
			tcp_client_write_ln (client, "%d;%s",
								base_code+3,
								text
								);
			if (text != NULL) free (text);
		}

		cd = (mydvb_content_descriptor *)
				 mydvb_descriptor_find (eit_entry->descriptors, 0x54);
		if (cd != NULL) {
			for (j = 0; j < cd->num_contents; j++) {
				tcp_client_write_ln (client, "%d;%s",
						base_code+4,
						mydvb_desc_content_table()[cd->content[j]]);
			}
		}
	}
}

void cmd_show_info (MYDVB_ENGINE *engine, TCP_CLIENT *client, mydvb_tuner_type_t type, int channel, int service) {
	int len;
	int i, j;
	mydvb_service_description *sd;
	MYDVB_PROGRAM *program;
	MYDVB_STREAM *stream;

	mydvb_service_descriptor *d;

	char *streamType = NULL;

	char *provider_name = NULL;
	char *service_name = NULL;

	MYDVB *mydvb = mydvb_get_channel (engine, type, channel);
	program = mydvb_get_program (engine, type, channel, service);

	if (program == NULL) {
		tcp_client_write_ln (client, "No info available");
		return;
	}

	sd = mydvb_get_service_description (mydvb, program->number);

	if (sd == NULL) {
		tcp_client_write_ln (client, "No info available");
		return;
	}

	d = (mydvb_service_descriptor * )
			mydvb_descriptor_find (sd->descriptors, 0x48);

	if (d == NULL) {
		tcp_client_write_ln (client, "No info available");
		return;
	}

	tcp_client_write_ln (client, "000; %d; %d",
			channel,
			service);

	provider_name = mydvb_text_to_utf8 (d->provider_name);
	service_name  = mydvb_text_to_utf8 (d->service_name);

	tcp_client_write_ln (client, "100; %d; %s; %s; %s; %s; Scram %d; EIT %d; EIT P/F %d",
			sd->number,
			provider_name, //d->provider_name->text,
			service_name, //d->service_name->text,
			mydvb_service_type_table()[d->service_type],
			mydvb_running_status_table()[sd->running_status],
			sd->scram,
			sd->eit,
			sd->eit_pw
			);
	free (service_name);
	free (provider_name);


	if (program->eit != NULL) {

		_show_eit_entry (client, 110, program->eit);

	}

	len = dyn_array_get_size (program->streams);
	for (i = 0; i < len; i++) {
		stream = (MYDVB_STREAM *) dyn_array_get_data (program->streams, i);

		if (stream->type >= MYDVB_STREAM_TYPE_LEN) {
			streamType = "Unknown";
		} else {
			streamType = mydvb_stream_type_table()[stream->type];
		}

		tcp_client_write_ln (client, "201;%d;PID %d;%s",
				i,
				stream->pid,
				streamType);
	}


	tcp_client_write_ln (client, "");
}

void cmd_epg (MYDVB_ENGINE *engine, TCP_CLIENT *client, mydvb_tuner_type_t type, int chn, int service) {

	int i;
	mydvb_service_description *sd;

	MYDVB *mydvb = mydvb_get_channel (engine, type, chn);

	if (mydvb == NULL) {
		tcp_client_write_ln (client, "No info available");
		return;
	}

	MYDVB_PROGRAM *program = mydvb_get_program_in_channel (mydvb, service);

	if (program == NULL) {
		tcp_client_write_ln (client, "No info available");
		return;
	}

	sd = mydvb_get_service_description (mydvb, program->number);

	if (sd == NULL) {
		tcp_client_write_ln (client, "No info available");
		return;
	}

	for (i = 0; i < 16 ; i++) {
		_show_eit_entry (client, 120, program->eit_sched[i]);
	}

	tcp_client_write_ln (client, "");

}

void cmd_move_service (APP_INFO *app_info, int chn_from, int chn_to) {

	info_dvb_move_channel (app_info->info_dvb, chn_from, chn_to);

	info_dvb_save (app_info->scan_file, app_info->info_dvb);
}

int scan_channel (APP_INFO *app_info, mydvb_tuner_type_t type, int chn) {
	properties *scan_props = NULL;
	MYDVB_TUNER_SCAN_PARAMETER scan;

	scan_props = properties_load (app_info->freq_file);

	scan.search_mode = MYDVB_TUNER_SEARCH_PARTIAL;
	scan.type = type;

	scan.param.t.f_step  = properties_get_long (scan_props, "f_step"); //8000000; // 8MHz bandwidth
	scan.param.t.f_start = properties_get_long (scan_props, "f_start") + scan.param.t.f_step * (chn - 21); // 474000000; // + 8000000*45; // 474000000;
	scan.param.t.f_end   = scan.param.t.f_start;

	properties_free (scan_props);

	app_info->scan_info = mydvb_tuner_search (&app_info->engine, &scan);
	if (app_info->scan_info==NULL) {
		return -1;
	}

	return 0;

}

int scan_all_channels (APP_INFO *app_info) {
	properties *scan_props = NULL;
	MYDVB_TUNER_SCAN_PARAMETER scan;

	scan_props = properties_load (app_info->freq_file);

	scan.search_mode = MYDVB_TUNER_SEARCH_FULL;
	scan.type = DVB_TYPE_DVBT;

	scan.param.t.f_start = properties_get_long (scan_props, "f_start"); // 474000000; // + 8000000*45; // 474000000;
	scan.param.t.f_end   = properties_get_long (scan_props, "f_end"); // 858000000;
	scan.param.t.f_step  = properties_get_long (scan_props, "f_step"); //8000000; // 8MHz bandwidth

	properties_free (scan_props);

	app_info->scan_info = mydvb_tuner_search (&app_info->engine, &scan);
	if (app_info->scan_info==NULL) {
		return -1;
	}

	return 0;

}

void terminal_end (MYDVB_ENGINE *engine, TCP_CLIENT *client) {

	int listener_id;

	listener_id = *((int *) client->extra);

	mydvb_remove_listener (engine, listener_id);

	tcp_client_disconnect (client);
}

void telnet_callback (MYDVB_ENGINE *engine, MYDVB_EVENT *event, void *data) {

	APP_INFO *app_info = (APP_INFO *) data;

	TCP_SERVER *server;
	TCP_CLIENT *client;

	int fd = event->external.fd;

	unsigned char cmd[1024];

	int net_port;
	char net_host[256];

	int chn, service;
	char aux[256];

	int i;

	int r; /* result variable for functions */

	int listener_id;

	server = app_info->server;

	if (fd == server->socket) {

		client = tcp_server_connect (server);

		if (client != NULL) {

			 mydvb_log (MYDVB_LOG_LEVEL_INFO, "Telnet client connected: %s:%d",
					 get_ip_by_addr (&client->addr, aux), client->addr.sin_port);

			 listener_id = mydvb_register_ext_listener (engine, client->socket, telnet_callback, app_info);

			 tcp_client_set_extra (client, &listener_id, sizeof (int));

			 client->mode = TCP_CLIENT_MODE_LOGIN;

			 tcp_client_write_ln (client, "DVBTransmitter command shell");
			 tcp_client_write (client, "User: ");


		}

	} else {

		client = tcp_server_get_client_by_socket (server, fd);

		if (client == NULL) {
			// client not found (why?)
			return;
		}

		if (tcp_client_read_ln (client, cmd) == NULL) { // closed by client disconnection

			terminal_end (engine, client);
			return;

		}

		if (strcmp (cmd, "") == 0) { /* error reading data */
			return;
		}

		if (cmd[0] == 0xff) { /* telnet command, ignore it for now */
			return;
		}

		if (client->mode == TCP_CLIENT_MODE_LOGIN) {

			char echo_off[4] = {0xFF, 0xFC, 0x01, 0x00};

			strcpy (client->user, cmd);

			tcp_client_write (client, "%s", echo_off); // echo off

			client->mode = TCP_CLIENT_MODE_PASSWORD;

		} else if (client->mode == TCP_CLIENT_MODE_PASSWORD) {

			tcp_client_write (client, "%c%c%c", 0xFF,0xFC,0x01); // echo on

			if (strcmp(client->user, "admin")==0 && strcmp (cmd,"pass")==0) {
				client->mode = TCP_CLIENT_MODE_CMD;
				tcp_client_write (client, "> ");
			} else {
				client->mode = TCP_CLIENT_MODE_LOGIN;
				tcp_client_write_ln (client, "Invalid username/password");
				tcp_client_write (client, "User: ");
			}


		} else if (client->mode == TCP_CLIENT_MODE_CMD) {

			if (strncmp (cmd, "help", 4) == 0) {

				cmd_help (client);

			} else if (strncmp (cmd, "engine", 6)==0) {

				cmd_engine (app_info, client);

			}  else if (strncmp (cmd, "tuners", 6)==0) {

				cmd_tuners (app_info, client);

			} else if (strncmp (cmd, "clients", 7)==0) {

				cmd_clients (app_info, client);

			} else if (strncmp (cmd, "channels", 4)==0) {

				cmd_channels (app_info->info_dvb, client);

			} else if (strncmp (cmd, "move", 4)==0) {

				int chn_from;
				int chn_to;

				sscanf (cmd, "move %d %d", &chn_from, &chn_to);
				cmd_move_service (app_info, chn_from, chn_to);

			} else if (strncmp (cmd, "stop", 4)==0) {

				if (app_info->broadcast == NULL) {

					tcp_client_write_ln (client, "broadcast is not enabled");

				} else {

					mydvb_tuner_release (engine, app_info->broadcast->tuner);
					app_info->broadcast->tuner = NULL;

				}

			} else if (strncmp (cmd, "broadcast", 9)==0) {

				int n;

				if (app_info->broadcast == NULL) {

					tcp_client_write_ln (client, "broadcast is not enabled");

				} else {

					sscanf (cmd, "broadcast %d %s %d", &n, net_host, &net_port);

					if (strcmp (net_host, "me")==0) {
						sprintf (net_host, "%s", get_ip_by_addr (&client->addr, aux));
					}

					mydvb_log (MYDVB_LOG_LEVEL_INFO, "Broadcast to %s %d", net_host, net_port);

					r = net_set_target (&app_info->broadcast->u.net_output, net_host, net_port);

					if (r != 0) {

						tcp_client_write_ln (client, "error: can't set the broadcast target");
					}

					INFO_PROGRAM *ip = info_dvb_get_by_user_number (app_info->info_dvb, n);

					if (ip == NULL) {

						tcp_client_write_ln (client, "program not found");

					} else {

						MYDVB_TUNE *tuner = tuner_program (engine, ip);

						if (tuner != NULL) {

							app_info->broadcast->tuner = tuner;

						} else {

							tcp_client_write_ln (client, "no tuners available");
						}
					}
				}

			} else if (strncmp (cmd, "scan", 4)==0) {

				sscanf (cmd, "scan %s", aux);

				if (strcmp (aux, "start")==0) {

					if (app_info->scan_info != NULL) {

						tcp_client_write_ln (client, "Can't start a new scan, scanning already in process");

					} else if (scan_all_channels (app_info)!=0) {

						tcp_client_write_ln (client, "scan start failed");
					}

				} else if (strcmp (aux, "stop")==0) {

					if (app_info->scan_info != NULL) {

						app_info->scan_info->status = MYDVB_SEARCH_STOPPED;

					} else {

						tcp_client_write_ln (client, "No scanning");
					}

				} else if (strcmp (aux, "cancel")==0) {

					if (app_info->scan_info != NULL) {

						app_info->scan_info->status = MYDVB_SEARCH_CANCELLED;

					} else {

						tcp_client_write_ln (client, "No scanning");
					}

				} else if (strcmp (aux, "status") == 0) {

					if (app_info->scan_info != NULL) {

						tcp_client_write_ln (client, "%d %d",
								mydvb_tune_get_uhf_channel (app_info->scan_info->scan->scan.t.f),
								app_info->scan_info->scan->scan.t.f);

						cmd_channels (app_info->scan_info->dvb_info, client);

					} else {

						tcp_client_write_ln (client, "No scanning");

					}

				} else if (strcmp (aux, "clean") == 0) {

					info_dvb_free (app_info->info_dvb);

					app_info->info_dvb = info_dvb_new ();

					info_dvb_save (app_info->scan_file, app_info->info_dvb);

				} else {
					/* check if this is a specific channel number
					 *
					 */
					if (app_info->scan_info == NULL) {

						int n = 20;

						n = atoi (aux);
						//n = strtol (aux, (char **)NULL, 10);

						scan_channel (app_info, DVB_TYPE_DVBT, n);

					} else {
						tcp_client_write_ln (client, "Can't start a new scan, scanning already in process");
					}

				}

			} else if (strncmp(cmd,"show", 4)==0) {

				int chn;
				int service;

				sscanf (cmd, "show %s %d/%d", aux, &chn, &service);

				mydvb_log (MYDVB_LOG_LEVEL_INFO, "show %s %d %d", aux, chn, service);

				cmd_show_info (engine, client, mydvb_tuner_parse_type (aux), chn, service);

			} else if (strncmp(cmd,"epg", 3)==0) {

				sscanf (cmd, "epg %s %d/%d", aux, &chn, &service);

				cmd_epg (engine, client, mydvb_tuner_parse_type (aux), chn, service);

			} else if (strcmp (cmd, "exit")==0) {

				terminal_end (engine, client);

			} else if (strcmp (cmd, "shutdown")==0) {

				mydvb_end_main_loop (&app_info->engine);

				tcp_client_write_ln (client, "bye");

			} else {

				tcp_client_write_ln (client, "error: unknown command");

			}

			tcp_client_write (client, "> ");
		}

	}

}

int http_local_handler (HTTP_RESPONSE *response, APP_INFO *app_info) {

	HTTP_REQUEST *request = response->request;
	MYDVB_ENGINE *engine = &app_info->engine;

	if (strcmp ("/stream/tv.html", request->uri) == 0) {

		char *type = properties_get (request->parameters, "type");
		int chn    = properties_get_int (request->parameters, "channel");
		int number = properties_get_int (request->parameters, "program");

		mydvb_log (MYDVB_LOG_LEVEL_INFO, "HTTP program %s %d/%d", type, chn, number);

		INFO_PROGRAM *p = info_dvb_find (app_info->info_dvb, mydvb_tuner_parse_type(type), chn, number);

		MYDVB_TUNE *tuner = tuner_program (engine, p);

		if (tuner) {
			response->status=200;
			response->reason="OK";

			properties_add (response->headers, "Content-Type", "video/mp2t");
			properties_add (response->headers, "Transfer-Encoding", "chunked");

			STREAM_OUTPUT *so = (STREAM_OUTPUT *) malloc (sizeof(STREAM_OUTPUT));
			dyn_array_add (app_info->receivers, &so);

			so->type = OUTPUT_TYPE_HTTP;
			so->tuner = tuner;
			so->u.http_output.response = response;


			return 2;

		} else {
			http_server_send_not_found (response);

			return 1;
		}
	}

	return 0;
}

void record_stream_callback (MYDVB_ENGINE *engine, MYDVB_EVENT *event, void *data) {

	STREAM_OUTPUT *so = (STREAM_OUTPUT *) data;

	ssize_t n=0;
	static unsigned char buffer[2*4096];

	n = fread(buffer, 1, sizeof(buffer), so->u.record_output.f);

	if (n == 0) {

		mydvb_log (MYDVB_LOG_LEVEL_INFO, "End of file transmission");

		// send end of chunked
		stream_output_send (so, buffer, n);

		int listener_id = so->u.record_output.listener_id;

		mydvb_remove_listener (engine, listener_id);

		stream_output_close (so);

	} else if (stream_output_send (so, buffer, n) < 0) {

		int listener_id = so->u.record_output.listener_id;

		mydvb_remove_listener (engine, listener_id);

		stream_output_close (so);

	}

}

void http_callback (MYDVB_ENGINE *engine, MYDVB_EVENT *event, void *data) {

	APP_INFO *app_info = (APP_INFO *) data;

	int fd = event->external.fd;

	int listener_id;

	HTTP_SERVER *server = app_info->http;

	HTTP_CLIENT *client;

	HTTP_REQUEST *request;

	HTTP_RESPONSE *response;

	int r;

	unsigned char body[8192];
	char *aux;

	if (fd == server->socket) {
		client = http_server_open_client (server);

		if (client != NULL) {
			listener_id = mydvb_register_ext_listener (engine, client->socket, http_callback, app_info);

			http_server_set_client_data (client, &listener_id, sizeof (int));
		}

	} else {
		client = http_server_find_client_by_fd (server, fd);

		if (client == NULL) {
			return;
		}

		request = http_server_request_new (client);
		if (request == NULL) { // client has closed

			listener_id = *((int *) client->data);

			mydvb_remove_listener (engine, listener_id);

			// remove from receiver
			for (int i = 0; i < dyn_array_get_size (app_info->receivers); i++) {

				STREAM_OUTPUT *output = *((STREAM_OUTPUT **) dyn_array_get_data (app_info->receivers, i));

				if (output->type == OUTPUT_TYPE_HTTP) {

					if (output->u.http_output.response->request->client == client) {

						mydvb_tuner_release (engine, output->tuner);

						stream_output_close (output);

						// remove from receivers
						dyn_array_remove(app_info->receivers, i);

						break;

					}

				}
			}

			http_server_close_client (client);

		} else {

			response = http_server_response (server, request);

			r = http_local_handler (response, app_info);
			if (r == 0) {
				r = dvbviewer_handler (response, app_info);
			}

			if (r == 0) {
				http_server_send_not_found (response);

				http_server_response_free (response);

				http_server_request_free (request);

			} else if (r == 1) {

				http_server_response_free (response);

				http_server_request_free (request);
			}

		}
	}
}


void search_callback (MYDVB_ENGINE *engine, MYDVB_EVENT *event, void *data) {

	APP_INFO *app_info = (APP_INFO *) data;

	INFO_DVB *dvb = event->search.info_dvb;

	if (dvb == NULL) {
		return;
	}

	if (event->search.status == MYDVB_SEARCH_COMPLETED ||
		event->search.status == MYDVB_SEARCH_STOPPED) {

		if (app_info->scan_info->scan->search_mode == MYDVB_TUNER_SEARCH_PARTIAL) {

			info_dvb_merge (app_info->info_dvb, dvb);

		} else {

			info_dvb_free (app_info->info_dvb);

			app_info->info_dvb = info_dvb_new ();

			info_dvb_merge (app_info->info_dvb, dvb);
		}

		info_dvb_save (app_info->scan_file, app_info->info_dvb);

		info_dvb_free (dvb);

	} else if (event->search.status == MYDVB_SEARCH_CANCELLED) {

		info_dvb_free (dvb);

	}

	app_info->scan_info = NULL;

}


void tuner_callback (MYDVB_ENGINE *engine, MYDVB_EVENT *event, void *data) {

	if (event->tuner.status == TUNER_STATUS_LOCK) {

		mydvb_log (MYDVB_LOG_LEVEL_DEBUG, "Starting decoder");

		mydvb_start_decoder (engine, event->tuner.tuner);

	}
}

/**
 * Invoked by the dvb system when there are data in the vdr device
 */
void data_reader_callback (MYDVB_ENGINE *engine, MYDVB_EVENT *event, void *data) {

	APP_INFO *app_info = (APP_INFO *) data;
	int i;

	// send to receivers
	for (i = 0; i < dyn_array_get_size (app_info->receivers); i++) {

		STREAM_OUTPUT *output = *((STREAM_OUTPUT **) dyn_array_get_data (app_info->receivers, i));

		if (event->stream.tuner != output->tuner) {
			continue;
		}

		if (stream_output_send (output, event->stream.buffer, event->stream.length) < 0) {

			mydvb_tuner_release (engine, output->tuner);

			stream_output_close (output);

			// remove from receivers
			dyn_array_remove(app_info->receivers, i);
			i--;

		}

	}

	total_bytes += event->stream.length;

}

/**
 * called 1 time per second
 */
void timeout_callback (MYDVB_ENGINE *engine, MYDVB_EVENT *event, void *data) {

	APP_INFO *app_info = (APP_INFO *) data;

	// auto-scan when channel list is empty
	if (app_info->info_dvb->channels_len == 0) { // scan required

		if (event->timeout.count > app_info->next_autoscan) {

			mydvb_log (MYDVB_LOG_LEVEL_INFO, "Auto scanning start");

			app_info->next_autoscan = event->timeout.count + 30*60*1000;

			scan_all_channels (app_info);

		}
	}

	// recorder manager
	if (dyn_array_get_size (app_info->recorder->progs) > 0) {

		PROG *p = *((PROG **) dyn_array_get_data (app_info->recorder->progs, 0));

		// check if current recording must finish
		if (p->status == 'R' && p->end <= event->timeout.count) {

			mydvb_log (MYDVB_LOG_LEVEL_INFO, "Recording finished: %s", p->title);

			if (p->out != NULL) {

				mydvb_tuner_release (engine, p->out->tuner);

				stream_output_close (p->out);

				// remove from receivers
				for (int i = 0; i < dyn_array_get_size (app_info->receivers); i++) {
					STREAM_OUTPUT *so = *((STREAM_OUTPUT **) dyn_array_get_data(app_info->receivers, i));

					if (so == p->out) {
						dyn_array_remove(app_info->receivers, i);
						break;
					}
				}

				p->out = NULL;
			}

			p->status = 'C';

			recorder_save (app_info->recorder);

			recorder_sort (app_info->recorder);

		}

		if (p->status == 'W' && p->start <= event->timeout.count
				&& p->end > event->timeout.count) {

			char fn[4096];

			INFO_PROGRAM *ip = info_dvb_find (app_info->info_dvb, p->type, p->channel, p->service);

			if (ip == NULL) {
				mydvb_log (MYDVB_LOG_LEVEL_ERROR, "Program '%s' not found at %s %d/%d", p->title, mydvb_tuner_type_table()[p->type], p->channel, p->service);
				return;
			}

			mydvb_log (MYDVB_LOG_LEVEL_INFO, "Program '%s' found at %s %d/%d", p->title, mydvb_tuner_type_table()[p->type], p->channel, p->service);

			MYDVB_TUNE *tuner = tuner_program (engine, ip);

			if (!tuner) {
				mydvb_log (MYDVB_LOG_LEVEL_INFO, "No tuners available, can't start recording '%s' at %s %d/%d", p->title, mydvb_tuner_type_table()[p->type], p->channel, p->service);
				return;
			}

			mydvb_log (MYDVB_LOG_LEVEL_INFO, "Tuner available");

			STREAM_OUTPUT *fileout;

			prog_get_file_path (p, fn);

			fileout = open_file_output (fn);

			if (fileout == NULL) {
				mydvb_log (MYDVB_LOG_LEVEL_ERROR, "Can't open file for recording %s", fn);

				mydvb_tuner_release (engine, tuner);

				return;
			}

			fileout->tuner  = tuner;

			dyn_array_add (app_info->receivers, &fileout);

			p->out 			= fileout;
			p->status 		= 'R';

			recorder_save (app_info->recorder);

			mydvb_log (MYDVB_LOG_LEVEL_INFO, "Recording started: %s", p->title);

		}
	}

}

/**
 * invoked by the dvb system when the started program is ready
 */
void program_callback (MYDVB_ENGINE *engine, MYDVB_EVENT *event, void *data) {
	int len, i;
	MYDVB_STREAM *stream;
	MYDVB_PROGRAM *program;

	program = event->program.program;

	/* we want all streams, so start all of them */
	len = dyn_array_get_size (program->streams);
	for (i=0; i < len; i++) {
			stream = dyn_array_get_data (program->streams, i);
			mydvb_start_stream (event->program.tuner, stream);
	}

}

/**
 * invoked by the dvb system when it is ready
 */
void channel_ready_callback (MYDVB_ENGINE *engine, MYDVB_EVENT *event, void *data) {

	// channel is ready
	INFO_PROGRAM *info_program = (INFO_PROGRAM *) event->ready.tuner->data;

	MYDVB_PROGRAM *program = mydvb_get_program (engine
			, info_program->channel->type
			, info_program->channel->n
			, info_program->n);

	mydvb_start_program (engine, event->ready.tuner, program);
				
}

void show_usage () {
	fprintf (stdout, "Usage:\n");
	fprintf (stdout, "dvbtrans [-c <config file>]\n");
	fprintf (stdout, "where:\n");
	fprintf (stdout, "<config file> is the configuration file for this transmitter\n");
}

/**
 * The main function
 */
int main (int argc, char *argv[]) {

	char conf_file[1024];

	int net_port;
	char *net_host;

	char *file_name;

	int n;

	int terminal_port = 8888;

	int http_port = 8089;

	properties *conf;

	char *logger_level = NULL;
	char *logger_file  = NULL;

	int c = '?';
	int option_index = 0;
	static const char *short_options = "?hc:";
	static struct option long_options[] = {
		{"help"           , no_argument      , 0, 'h'                 },
		{"config"         , no_argument      , 0, 'c'                 },
		{0                , no_argument      , 0,  0                  }
	};

	app_info.scan_info = NULL;

	/* --------------------------------------------------------- */
	/* ----- Argument parsing ---------------------------------- */
	/* --------------------------------------------------------- */
	while((c = getopt_long(argc, argv, short_options, long_options, &option_index)) != EOF) {

		switch (c) {

			case 'c':

				sprintf (conf_file, "%s", optarg);

				break;

			case 'h':

			case '?':
				show_usage ();

				return 0;

				break;
		}
	}


	/* --------------------------------------------------------- */
	/* -------------- daemonize -------------------------------- */
	/* --------------------------------------------------------- */
	daemonize ("/var/run/dvbtrans.pid");

	/* --------------------------------------------------------- */
	/* -------------- set some signals handlers ---------------- */
	/* --------------------------------------------------------- */
	signal (SIGTERM, sig_term); /* sig term */

	signal (SIGINT, sig_term);  /* ^C */


	/* --------------------------------------------------------- */
	/* read config file */
	/* --------------------------------------------------------- */

	conf = properties_load (conf_file);

	if (conf == NULL) {
		fprintf (stderr, "Can't load the configuration file '%s'\n", conf_file);

		return -1;
	}

	/* logger */
	logger_level = properties_get (conf, "logger.level");

	if (logger_level != NULL) {

		mydvb_log_level_t level = mydvb_log_parse_level (logger_level);

		logger_file = properties_get (conf, "logger.file");

		mydvb_log_open (level, logger_file);
	}

	mydvb_log (MYDVB_LOG_LEVEL_INFO, "DVBTransmitter initializing");

	app_info.receivers = dyn_array_new (sizeof (STREAM_OUTPUT *));
	dyn_array_set_free_callback (app_info.receivers, _free_stream_output);

	/* parsing output */
	n = 0;
	if (strcmp ("yes", properties_get (conf, "broadcast")) == 0) {

		net_port = properties_get_int (conf, "broadcast.port");

		net_host = properties_get (conf, "broadcast.host");

		app_info.broadcast = open_net_output (net_host, net_port);

		if (app_info.broadcast == NULL) {
			mydvb_log (MYDVB_LOG_LEVEL_ERROR, "Can't open broadcast host. Broadcast disabled");

		} else {
			dyn_array_add (app_info.receivers, &app_info.broadcast);

			mydvb_log (MYDVB_LOG_LEVEL_INFO, "Broadcast mode enabled to %s:%d", net_host, net_port);
		}

	}

	if (strcmp ("yes", properties_get (conf, "dumping")) == 0) {

		STREAM_OUTPUT *fileout;

		file_name = properties_get (conf, "dumping.file");

		fileout = open_file_output (file_name);

		if (fileout == NULL) {
			mydvb_log (MYDVB_LOG_LEVEL_ERROR, "Can't open dumping file. Dumping disabled");

		} else {
			dyn_array_add (app_info.receivers, &fileout);
		}
	}

	/* --------------------------------------------------------- */
	/* --- startup the http server at the specified port ------- */
	/* --------------------------------------------------------- */
	http_port = properties_get_int (conf, "http.port");
	app_info.http = http_server_init (http_port);
	app_info.http->root = properties_get (conf, "http.root");

	if (app_info.http == NULL) {
		mydvb_log (MYDVB_LOG_LEVEL_ERROR, "Failed to initialize the http server: %s", strerror(errno));
		mydvb_log (MYDVB_LOG_LEVEL_INFO, "No http server available");
	} else {
		mydvb_log (MYDVB_LOG_LEVEL_INFO, "HTTP Server running at %d", http_port);
	}


	/* --------------------------------------------------------- */
	/* --- startup the terminal server at the specified port ----- */
	/* --------------------------------------------------------- */
	terminal_port = properties_get_int (conf, "terminal.port");
	app_info.server = tcp_server_create (terminal_port);

	if (app_info.server == NULL) {
		mydvb_log (MYDVB_LOG_LEVEL_ERROR, "Failed to initialize the terminal server: %s", strerror(errno));
		mydvb_log (MYDVB_LOG_LEVEL_INFO, "No terminal server available");

	} else {
		mydvb_log (MYDVB_LOG_LEVEL_INFO, "Terminal Server running at port %d", terminal_port);
	}


	/* --------------------------------------------------------- */
	/* --- initialize the recorder ----------------------------- */
	/* --------------------------------------------------------- */

	// recorder=yes

	app_info.recorder = recorder_new ();
	app_info.recorder->directory = strdup (properties_get(conf, "recorder.directory"));
	recorder_set_storage (app_info.recorder, properties_get(conf,"recorder.file"));


	/* --------------------------------------------------------- */
	/* --- read the channels file ------------------------------ */
	/* --------------------------------------------------------- */
	app_info.freq_file = properties_get_default (conf, "freq.file", "/etc/dvb/weurope.txt");

	app_info.scan_file = properties_get (conf, "scan.file");

	app_info.info_dvb = info_dvb_new ();

	app_info.next_autoscan = 0;

	info_dvb_load (app_info.scan_file, app_info.info_dvb);
	
	// initialize mydvb engine
	mydvb_engine_init (&app_info.engine);

	// add some listeners
	mydvb_register_listener (&app_info.engine, MYDVB_EVENT_READY, channel_ready_callback, &app_info);

	mydvb_register_listener (&app_info.engine, MYDVB_TUNER_EVENT, tuner_callback, &app_info);

	mydvb_register_listener (&app_info.engine, MYDVB_EVENT_STREAM, data_reader_callback, &app_info);

	mydvb_register_listener (&app_info.engine, MYDVB_EVENT_PROGRAM, program_callback, NULL);

	mydvb_register_listener (&app_info.engine, MYDVB_SEARCH_EVENT, search_callback, &app_info);

	mydvb_register_listener (&app_info.engine, MYDVB_TIMEOUT_EVENT, timeout_callback, &app_info);

	mydvb_register_ext_listener (&app_info.engine, app_info.server->socket, telnet_callback, &app_info);

	mydvb_register_ext_listener (&app_info.engine, app_info.http->socket, http_callback, &app_info);

	/* start up the main loop */
	mydvb_main_loop (&app_info.engine);

	mydvb_engine_end (&app_info.engine);
	
	info_dvb_free (app_info.info_dvb);

	recorder_free (app_info.recorder);

	tcp_server_free (app_info.server);

	http_server_end (app_info.http);

	dyn_array_free (app_info.receivers);

	properties_free (conf);

	mydvb_log (MYDVB_LOG_LEVEL_INFO, "DVBTransmitter end");

	mydvb_log_close ();

	return 0;
}
