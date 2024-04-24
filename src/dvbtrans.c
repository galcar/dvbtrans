

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
#include "charset.h"

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

	mydvb_end_main_loop (app_info.mydvb);

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

	char *ip;

	ip = get_ip_by_host (net_host);

	if (ip==NULL) {
		return -1;
	}

	bzero((unsigned char *) &no->target, sizeof(no->target));
	no->target.sin_family=AF_INET;
	no->target.sin_port=htons(net_port);
	no->target.sin_addr.s_addr=inet_addr(ip);

	free (ip);

	return 0;
}

STREAM_OUTPUT *open_net_output (const char *net_host, int net_port) {

	STREAM_OUTPUT *so = (STREAM_OUTPUT *) malloc (sizeof(STREAM_OUTPUT));

	if (net_set_target (&so->net_output, net_host, net_port) == -1) {
		free (so);
		return NULL;
	}

	if((so->net_output.sockfd=socket(AF_INET,SOCK_DGRAM,IPPROTO_UDP))==-1) {
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

	fileout->file_output.f = fopen (file_name, "w+b");
	if (!fileout->file_output.f) {
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
			if (so->net_output.sockfd!=-1) {
				close (so->net_output.sockfd);
				so->net_output.sockfd = -1;
			}
			break;
		case OUTPUT_TYPE_FILE:
			if (so->file_output.f != NULL) {
				fclose (so->file_output.f);
				so->file_output.f = NULL;
			}
			break;

		case OUTPUT_TYPE_HTTP:
			response = so->http_output.response;
			http_server_request_free (response->request);
			http_server_response_free (response);
			break;

		case OUTPUT_TYPE_RECORD:
			response = so->record_output.response;
			http_server_request_free (response->request);
			http_server_response_free (response);

			if (so->record_output.f != NULL) {
				fclose (so->record_output.f);
				so->record_output.f = NULL;
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

			n = send_broadcast (so->net_output.sockfd, buf, len, &so->net_output.target);
			break;

		case OUTPUT_TYPE_FILE:

			if (so->file_output.f != NULL) {

				n = len * fwrite (buf, len, 1, so->file_output.f);

				if (ferror (so->file_output.f)) {
					mydvb_log (MYDVB_LOG_LEVEL_ERROR, "Error writing to file %s", strerror (errno));
					n = -1;
				}

			} else {
				n = -1;
			}
			break;

		case OUTPUT_TYPE_HTTP:
			receiver = so->http_output.response;

			n = http_server_send_chunked (receiver, buf,  len);
			if (n < 0) {
				mydvb_log (MYDVB_LOG_LEVEL_ERROR, "Http Streaming error: %s", strerror (errno));
			}
			break;

		case OUTPUT_TYPE_RECORD:
			receiver = so->record_output.response;

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


void cmd_list (INFO_DVB *dvb, TCP_CLIENT *client) {

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
					tcp_client_write_ln (client, "%d/%d;%s;%s;%d;%d:%d",
							mydvb_tune_get_channel (p->frequency),
							iprogram->n,
							(unsigned char *) (provider==NULL ? EMPTY_STRING : provider),
							(unsigned char *) (service ==NULL ? EMPTY_STRING : service),
							iprogram->type,
							iprogram->scrambled,
							iprogram->user_number
							);
					if (provider) free (provider);
					if (service) free (service);
				}
			}
		}
	}

	tcp_client_write_ln (client, "");
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
			mydvb_running_status_table[eit_entry->running_status],
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
						mydvb_desc_content_table[cd->content[j]]);
			}
		}
	}
}

void cmd_show_info (MYDVB *mydvb, TCP_CLIENT *client, int channel, int service) {
	int len;
	int i, j;
	mydvb_service_description *sd;
	MYDVB_PROGRAM *program;
	MYDVB_STREAM *stream;

	mydvb_service_descriptor *d;

	char *streamType = NULL;

	char *provider_name = NULL;
	char *service_name = NULL;


	program = mydvb_get_program_by_number (mydvb, service);

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
			mydvb_service_type_table[d->service_type],
			mydvb_running_status_table[sd->running_status],
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
			streamType = mydvb_stream_type_table[stream->type];
		}

		tcp_client_write_ln (client, "201;%d;PID %d;%s",
				i,
				stream->pid,
				streamType);
	}



	tcp_client_write_ln (client, "");
}

void cmd_epg (MYDVB *mydvb, TCP_CLIENT *client, int service) {

	int i;
	mydvb_service_description *sd;
	MYDVB_PROGRAM *program;


	program = mydvb_get_program_by_number (mydvb, service);

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

void scan_all_channels (APP_INFO *app_info) {
	properties *scan_props = NULL;
	MYDVB_TUNE_SCAN_PARAMETER scan;

	scan_props = properties_load (app_info->freq_file);

	scan.search_mode = MYDVB_TUNE_SEARCH_FULL;

	scan.param.t.f_start = properties_get_long (scan_props, "f_start"); // 474000000; // + 8000000*45; // 474000000;
	scan.param.t.f_end   = properties_get_long (scan_props, "f_end"); // 858000000;
	scan.param.t.f_step  = properties_get_long (scan_props, "f_step"); //8000000; // 8MHz bandwidth

	properties_free (scan_props);

	app_info->scan_info = mydvb_tune_search (app_info->mydvb, &scan);

}

void terminal_end (MYDVB *mydvb, TCP_CLIENT *client) {

	int listener_id;

	listener_id = *((int *) client->extra);

	mydvb_remove_listener (mydvb, listener_id);

	tcp_client_disconnect (client);
}

void telnet_callback (MYDVB *mydvb, MYDVB_EVENT *event, void *data) {

	APP_INFO *app_info = (APP_INFO *) data;

	TCP_SERVER *server;
	TCP_CLIENT *client;

	int fd = event->external.fd;

	unsigned char *cmd = NULL;

	int number;

	int net_port;
	char net_host[256];

	char aux[256];

	int i;

	int r; /* result variable for functions */

	int listener_id;

	server = app_info->server;

	if (fd == server->socket) {

		client = tcp_server_connect (server);

		if (client != NULL) {

			 mydvb_log (MYDVB_LOG_LEVEL_INFO, "Telnet client connected: %s:%d",
					 get_ip_by_addr (&client->addr), client->addr.sin_port);

			 listener_id = mydvb_register_ext_listener (mydvb, client->socket, telnet_callback, app_info);

			 tcp_client_set_extra (client, &listener_id, sizeof (int));

			 tcp_client_write_ln (client, "ok");
		}

	} else {

		client = tcp_server_get_client_by_socket (server, fd);

		if (client != NULL) {

			cmd = tcp_client_read_ln (client);

			if (cmd == NULL) { // closed by client disconnection

				terminal_end (mydvb, client);

			} else if (strcmp (cmd, "") == 0) { /* error reading data */

			} else if (strncmp (cmd, "push", 4)==0) {

				sscanf (cmd, "push %d/%d", &(app_info->channumber), &(app_info->number));

				mydvb_log (MYDVB_LOG_LEVEL_INFO, "push stream %d/%d", app_info->channumber, app_info->number);

				/* safely call end decoder for stopping any previous decoding */
				mydvb_end_decoder (mydvb);

				r = mydvb_tune_channel_by_number (mydvb, app_info->info_dvb, app_info->channumber);

				if (r == 0) {

					tcp_client_write_ln (client, "ok");

				} else {

					tcp_client_write_ln (client, "error: can't tune the channel");
				}

			} else if (strcmp (cmd, "stop")==0) {

				mydvb_end_decoder (mydvb);

				tcp_client_write_ln (client, "ok");

			} else if (strncmp (cmd, "list", 4)==0) {

				cmd_list (app_info->info_dvb, client);

			} else if (strncmp (cmd, "broadcast", 8)==0) {

				sscanf (cmd, "broadcast %s %d", net_host, &net_port);

				if (strcmp (net_host, "me")==0) {
					sprintf (net_host, "%s", get_ip_by_addr (&client->addr));
				}

				mydvb_log (MYDVB_LOG_LEVEL_INFO, "Broadcast to %s %d", net_host, net_port);

				r = -1;
				for (i=0; i < dyn_array_get_size (app_info->receivers); i++) {
					STREAM_OUTPUT *so = *((STREAM_OUTPUT **) dyn_array_get_data (app_info->receivers, i));
					if (so->type == OUTPUT_TYPE_NET) {
						r = net_set_target (&so->net_output, net_host, net_port);
						break;
					}
				}

				if (r == 0) {

					tcp_client_write_ln (client, "ok");

				} else {

					tcp_client_write_ln (client, "error: can't set the broadcast target");
				}

			} else if (strncmp (cmd, "search", 6)==0) {

				sscanf (cmd, "search %s", aux);

				if (strcmp (aux, "start")==0) {

					scan_all_channels (app_info);

					tcp_client_write_ln (client, "ok");

				} else if (strcmp (aux, "stop")==0) {

					if (app_info->scan_info != NULL) {

						app_info->scan_info->status = MYDVB_SEARCH_STOPPED;

						tcp_client_write_ln (client, "ok");

					} else {

						tcp_client_write_ln (client, "No searching");
					}

				} else if (strcmp (aux, "cancel")==0) {

					if (app_info->scan_info != NULL) {

						app_info->scan_info->status = MYDVB_SEARCH_CANCELLED;

						tcp_client_write_ln (client, "ok");

					} else {

						tcp_client_write_ln (client, "No searching");
					}

				} else if (strcmp (aux, "status") == 0) {

					if (app_info->scan_info != NULL) {

						tcp_client_write_ln (client, "%d %d",
								mydvb_tune_get_channel (app_info->scan_info->scan->scan.t.f),
								app_info->scan_info->scan->scan.t.f);

						cmd_list (app_info->scan_info->dvb_info, client);

					} else {

						tcp_client_write_ln (client, "No searching");

					}

				} else if (strcmp (aux, "clean") == 0) {

					info_dvb_free (app_info->info_dvb);

					app_info->info_dvb = info_dvb_new ();

					info_dvb_save (app_info->scan_file, app_info->info_dvb);

					tcp_client_write_ln (client, "ok");

				} else {
					/* check if this is a specific channel number
					 *
					 */
					int n = 20;
					MYDVB_TUNE_SCAN_PARAMETER scan;

					n = atoi (aux);

					scan.search_mode = MYDVB_TUNE_SEARCH_PARTIAL;

					scan.param.t.f_step  = 8000000; // 8MHz bandwidth
					scan.param.t.f_start = 474000000 + scan.param.t.f_step * (n-21);
					scan.param.t.f_end   = scan.param.t.f_start;


					app_info->scan_info = mydvb_tune_search (mydvb, &scan);

					tcp_client_write_ln (client, "ok");
				}


			} else if (strcmp(cmd,"signal")==0) {

				mydvb_tune_get_info (&mydvb->mytune);

				tcp_client_write_ln (client, "%s; frequency: %d; strength: %d; snr: %d; ber: %d",
						mydvb->mytune.name,
						mydvb->mytune.p.frequency,
						mydvb->mytune.info.signal,
						mydvb->mytune.info.snr,
						mydvb->mytune.info.ber);


			} else if (strncmp(cmd,"show", 4)==0) {

				cmd_show_info (mydvb, client, app_info->channumber, app_info->number);

			} else if (strncmp(cmd,"epg", 3)==0) {

				cmd_epg (mydvb, client, app_info->number);

			} else if (strcmp (cmd, "exit")==0) {

				terminal_end (mydvb, client);

			} else if (strcmp (cmd, "shutdown")==0) {

				mydvb_end_main_loop (app_info->mydvb);

				tcp_client_write_ln (client, "bye");

			} else {

				tcp_client_write_ln (client, "error: unknown command");
			}

			if (cmd != NULL) {
				free (cmd);
				cmd = NULL;
			}
		}

	}

}

int http_local_handler (HTTP_RESPONSE *response, APP_INFO *app_info) {

	HTTP_REQUEST *request = response->request;
	MYDVB *mydvb = app_info->mydvb;

	int r;

	if (strcmp ("/stream/tv.html", request->uri) == 0) {

		app_info->channumber = properties_get_int (request->parameters, "channel");
		app_info->number	 = properties_get_int (request->parameters, "program");

		mydvb_log (MYDVB_LOG_LEVEL_INFO, "HTTP program %d/%d", app_info->channumber, app_info->number);

		/* safely call end decoder for stopping any previous decoding */
		mydvb_end_decoder (mydvb);

		r = mydvb_tune_channel_by_number (mydvb, app_info->info_dvb, app_info->channumber);

		if (r == 0) {
			response->status=200;
			response->reason="OK";

			properties_add (response->headers, "Content-Type", "video/mp2t");
			properties_add (response->headers, "Transfer-Encoding", "chunked");

			STREAM_OUTPUT *so = (STREAM_OUTPUT *) malloc (sizeof(STREAM_OUTPUT));
			dyn_array_add (app_info->receivers, &so);

			so->http_output.type = OUTPUT_TYPE_HTTP;
			so->http_output.response = response;


			return 2;

		} else {
			http_server_send_not_found (response);

			return 1;
		}
	}

	return 0;
}

void record_stream_callback (MYDVB *mydvb, MYDVB_EVENT *event, void *data) {

	STREAM_OUTPUT *so = (STREAM_OUTPUT *) data;

	int fd = event->external.fd;

	ssize_t n=0;
	static unsigned char buffer[2*4096];

	n = fread(buffer, 1, sizeof(buffer), so->record_output.f);

	if (n == 0) {

		mydvb_log (MYDVB_LOG_LEVEL_INFO, "End of file transmission");

		// send end of chunked
		stream_output_send (so, buffer, n);

		int listener_id = so->record_output.listener_id;
		stream_output_close (so);

		mydvb_remove_listener (mydvb, listener_id);

	} else if (stream_output_send (so, buffer, n) < 0) {

		int listener_id = so->record_output.listener_id;
		stream_output_close (so);

		mydvb_remove_listener (mydvb, listener_id);

	}

}

void http_callback (MYDVB *mydvb, MYDVB_EVENT *event, void *data) {

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
			listener_id = mydvb_register_ext_listener (mydvb, client->socket, http_callback, app_info);

			http_server_set_client_data (client, &listener_id, sizeof (int));
		}

	} else {
		client = http_server_find_client_by_fd (server, fd);

		request = http_server_request_new (client);
		if (request == NULL) { // client has closed

			listener_id = *((int *) client->data);

			mydvb_remove_listener (mydvb, listener_id);

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


void search_callback (MYDVB *mydvb, MYDVB_EVENT *event, void *data) {

	APP_INFO *app_info = (APP_INFO *) data;

	INFO_DVB *dvb = event->search.info_dvb;

	if (dvb == NULL) {
		return;
	}

	if (event->search.status == MYDVB_SEARCH_COMPLETED ||
		event->search.status == MYDVB_SEARCH_STOPPED) {

		if (app_info->scan_info->scan->search_mode == MYDVB_TUNE_SEARCH_PARTIAL) {

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


void tune_callback (MYDVB *mydvb, MYDVB_EVENT *event, void *data) {

	APP_INFO *app_info = (APP_INFO *) data;

	if (event->tune.status == TUNE_STATUS_LOCK) {

		mydvb_log (MYDVB_LOG_LEVEL_DEBUG, "Starting decoder");

		mydvb_start_decoder (mydvb);

	}
}

/**
 * Invoked by the dvb system when there are data in the vdr device
 */
void data_reader_callback (MYDVB *mydvb, MYDVB_EVENT *event, void *data) {

	APP_INFO *app_info = (APP_INFO *) data;
	int i;

	// send to receivers
	for (i = 0; i < dyn_array_get_size (app_info->receivers); i++) {

		STREAM_OUTPUT *output = *((STREAM_OUTPUT **) dyn_array_get_data (app_info->receivers, i));
		if (stream_output_send (output, event->stream.buffer, event->stream.length) < 0) {

			stream_output_close (output);

			// remove from receivers
			dyn_array_remove(app_info->receivers, i);
			i--;

			if (dyn_array_get_size (app_info->receivers) == 0) {

				mydvb_end_decoder (mydvb);
			}
		}

	}

	total_bytes += event->stream.length;

}

/**
 * called 1 time per second
 */
void timeout_callback (MYDVB *mydvb, MYDVB_EVENT *event, void *data) {

	APP_INFO *app_info = (APP_INFO *) data;

	// recorder manager
	if (dyn_array_get_size (app_info->recorder->progs) > 0) {

		PROG *p = *((PROG **) dyn_array_get_data (app_info->recorder->progs, 0));

		// check if current recording must finish
		if (p->status == 'R' && p->end <= event->timeout.count) {

			mydvb_log (MYDVB_LOG_LEVEL_INFO, "Recording finished: %s", p->title);

			if (p->out != NULL) {

				stream_output_close (p->out);

				// remove from receivers
				for (int i = 0; i < dyn_array_get_size (app_info->receivers); i++) {
					STREAM_OUTPUT *so = *((STREAM_OUTPUT **) dyn_array_get_data(app_info->receivers, i));

					if (so == p->out) {
						dyn_array_remove(app_info->receivers, i);

						if (dyn_array_get_size (app_info->receivers) == 0) {

							mydvb_end_decoder (mydvb);
						}

						break;
					}
				}

				p->out = NULL;
				p->status = 'C';

				recorder_save (app_info->recorder);

				recorder_sort (app_info->recorder);

			}
		}

		if (p->status == 'W' && p->start <= event->timeout.count
				&& p->end > event->timeout.count) {

			int r = -1;
			char fn[4096];

			// this prog must start
			if (mydvb->ready) {  // busy
				if (p->channel == app_info->channumber && p->service == app_info->number) {
					r = 0;
				}
			} else {
				app_info->channumber = p->channel;
				app_info->number	 = p->service;

				/* safely call end decoder for stopping any previous decoding */
				mydvb_end_decoder (mydvb);

				r = mydvb_tune_channel_by_number (mydvb, app_info->info_dvb, app_info->channumber);
			}

			if (r == 0) {

				STREAM_OUTPUT *fileout;

				prog_get_file_path (p, fn);

				fileout = open_file_output (fn);

				if (fileout == NULL) {
					mydvb_log (MYDVB_LOG_LEVEL_ERROR, "Can't open file for recording %s", fn);
					return;
				} else {

					dyn_array_add (app_info->receivers, &fileout);

					p->out 		= fileout;
					p->status 	= 'R';

					recorder_save (app_info->recorder);

					mydvb_log (MYDVB_LOG_LEVEL_INFO, "Recording started: %s", p->title);

				}

			} else {

				mydvb_log (MYDVB_LOG_LEVEL_INFO, "DVB busy, can't start recording %s at %d/%d", p->title, p->channel, p->service);

			}
		}
	}

}

/**
 * invoked by the dvb system when the started program is ready
 */
void program_callback (MYDVB *mydvb, MYDVB_EVENT *event, void *data) {
	int len, i;
	MYDVB_STREAM *stream;
	MYDVB_PROGRAM *program;

	program = event->program.program;

	/* we want all streams, so start all of them */
	len = dyn_array_get_size (program->streams);
	for (i=0; i < len; i++) {
			stream = dyn_array_get_data (program->streams, i);
			mydvb_start_stream (mydvb, stream);
	}

}

/**
 * invoked by the dvb system when it is ready
 */
void ready_callback (MYDVB *mydvb, MYDVB_EVENT *event, void *data) {

	// channel is ready
	MYDVB_PROGRAM *program = NULL;
	APP_INFO *app_info = (APP_INFO *) data;

	program = mydvb_get_program_by_number (mydvb, app_info->number);
	mydvb_start_program (mydvb, program);
				
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

	MYDVB_LIST	   *dvb_list;

	MYDVB *mydvb = NULL;

	int n;

	int terminal_port = 8888;

	int http_port = 8089;

	properties *conf;

	char *dvb_type = NULL;

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

	/* logger facilities */
	logger_level = properties_get (conf, "logger.level");

	if (logger_level != NULL) {

		mydvb_log_level_t level = MYDVB_LOG_LEVEL_ERROR;

		if (strcmp ("debug",logger_level)==0) {

			level = MYDVB_LOG_LEVEL_DEBUG;

		} else if (strcmp ("error", logger_level)==0) {

			level = MYDVB_LOG_LEVEL_ERROR;

		} else if (strcmp ("info", logger_level)==0){

			level = MYDVB_LOG_LEVEL_INFO;

		}

		logger_file = properties_get (conf, "logger.file");

		mydvb_log_open (level, logger_file);
	}

	mydvb_log (MYDVB_LOG_LEVEL_INFO, "DVBTransmitter initializing");

	app_info.channumber = 0;
	app_info.number     = 0;

	app_info.receivers = dyn_array_new (sizeof (STREAM_OUTPUT *));
	dyn_array_set_free_callback (app_info.receivers, _free_stream_output);

	/* parsing output */
	n = 0;
	if (strcmp ("yes", properties_get (conf, "broadcast")) == 0) {

		STREAM_OUTPUT *netout;

		net_port = properties_get_int (conf, "broadcast.port");

		net_host = properties_get (conf, "broadcast.host");

		netout = open_net_output (net_host, net_port);

		if (netout == NULL) {
			mydvb_log (MYDVB_LOG_LEVEL_ERROR, "Can't open broadcast host. Broadcast disabled");

		} else {
			dyn_array_add (app_info.receivers, &netout);

			mydvb_log (MYDVB_LOG_LEVEL_INFO, "Broadcast mode enabled to %s:%d", net_host, net_port);
		}

	}

	if (strcmp ("yes", properties_get (conf, "dumping")) == 0) {

		STREAM_OUTPUT *fileout;

		file_name = properties_get (conf, "dumping.file");

		fileout = open_file_output (file_name);

		if (fileout == NULL) {
			mydvb_log (MYDVB_LOG_LEVEL_ERROR, "Can't dumping file. Dumping disabled");

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
	/* --- startup the telnet server at the specified port ----- */
	/* --------------------------------------------------------- */
	terminal_port = properties_get_int (conf, "terminal.port");
	app_info.server = tcp_server_create (terminal_port);

	if (app_info.server == NULL) {
		mydvb_log (MYDVB_LOG_LEVEL_ERROR, "Failed to initialize the telnet server: %s", strerror(errno));
		mydvb_log (MYDVB_LOG_LEVEL_INFO, "No telnet server available");

	} else {
		mydvb_log (MYDVB_LOG_LEVEL_INFO, "Telnet running at port %d", terminal_port);
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

	info_dvb_load (app_info.scan_file, app_info.info_dvb);
	
	// build the available list of dvb devices
	dvb_list = mydvb_list_new ();

	/* dvb type */
	dvb_type = properties_get (conf, "dvb.type");
	if (dvb_type == NULL) {
		dvb_type = "dvbt";
	}

	// find the apropiate dvb device
	if (strcmp (dvb_type, "dvbt")==0) {

		mydvb = mydvb_list_get_dvbt (dvb_list);

	} else if (strcmp (dvb_type, "dvbs")==0) {

		mydvb = mydvb_list_get_dvbs (dvb_list);

	} else if (strcmp (dvb_type, "dvbc")==0) {

		mydvb = mydvb_list_get_dvbc (dvb_list);

	}

	if (mydvb) {

		app_info.mydvb = mydvb;

		mydvb_init (mydvb);

		mydvb_register_listener (mydvb, MYDVB_EVENT_READY, ready_callback, &app_info);

		mydvb_register_listener (mydvb, MYDVB_TUNE_EVENT, tune_callback, &app_info);

		mydvb_register_listener (mydvb, MYDVB_EVENT_STREAM, data_reader_callback, &app_info);

		mydvb_register_listener (mydvb, MYDVB_EVENT_PROGRAM, program_callback, NULL);

		mydvb_register_ext_listener (mydvb, app_info.server->socket, telnet_callback, &app_info);

		mydvb_register_listener (mydvb, MYDVB_SEARCH_EVENT, search_callback, &app_info);

		mydvb_register_listener (mydvb, MYDVB_TIMEOUT_EVENT, timeout_callback, &app_info);

		mydvb_register_ext_listener (mydvb, app_info.http->socket, http_callback, &app_info);

		/* start up the main loop */
		mydvb_main_loop (mydvb);

		mydvb_tune_end (&mydvb->mytune);

		mydvb_end (mydvb);


	}
	
	info_dvb_free (app_info.info_dvb);

	mydvb_list_free (dvb_list);

	recorder_free (app_info.recorder);

	tcp_server_free (app_info.server);

	http_server_end (app_info.http);

	dyn_array_free (app_info.receivers);

	properties_free (conf);

	mydvb_log_close ();

	return 0;
}
