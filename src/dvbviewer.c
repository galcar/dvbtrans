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
#include <string.h>

#include <sys/stat.h>
#include <sys/statvfs.h>

#include <mydvb_descriptors.h>
#include <mydvb_text.h>

#include "dvbviewer.h"

#include "recorder.h"

#include "dynarray.h"
#include "props.h"
#include "utils.h"

#define STR_CONCAT ("%s%s")
#define STR_CONCAT_SP ("%s %s")

/**
 * the program comparator used to create a list of ordered programs
 */
int _dvbviewer_program_comparator (void *p1, void *p2) {
	INFO_PROGRAM *ip1 = *((INFO_PROGRAM **) p1);
	INFO_PROGRAM *ip2 = *((INFO_PROGRAM **) p2);

	if (ip1->user_number == ip2->user_number) {
		return 0;
	} else if (ip1->user_number > ip2->user_number) {
		return 1;
	} else {
		return -1;
	}
}

/*
 * dvbviewer getxmlchannels format
 * "<?xml version=\"1.0\" encoding=\"UTF-8\"?><channels><root><group name=\"TV\"><channel nr=\"1\" name=\"La 1\" ID=\"%d\" flags=\"24\"></channel></group></root></channels>", id);
 */
char *_dvbviewer_create_channel_list (INFO_DVB *dvb) {

	int i, j;

	INFO_CHANNEL *ichannel = NULL;
	INFO_PROGRAM *iprogram = NULL;

	char *group;
	char group_tv[8192];
	char group_radio[8192];

	int chn, prog;
	long id;
	int flags;
	long epg_id = 0;
	int num_channel = 0;

	char *buf = (char *) malloc (8192*4*sizeof(char));

	unsigned char *utf8;
	char *aux = NULL;

	DYN_ARRAY *program_list = NULL;


	program_list = dyn_array_new (sizeof (INFO_PROGRAM *));
	dyn_array_set_comparator (program_list, _dvbviewer_program_comparator);

	for (i=0; i < dvb->channels_len; i++) {
		ichannel = dvb->channels[i];
		for (j=0; j < ichannel->programs_len; j++) {
			iprogram = ichannel->programs[j];
			dyn_array_add (program_list, &iprogram);
		}
	}
	dyn_array_quicksort (program_list);

	sprintf (buf, "<?xml version=\"1.0\" encoding=\"UTF-8\"?>");
	sprintf (buf, "%s<channels><root>", buf);

	sprintf (group_tv, "<group name=\"TV\">");
	sprintf (group_radio, "<group name=\"RADIO\">");

	for (i=0; i < dyn_array_get_size (program_list); i++) {
		iprogram = *((INFO_PROGRAM **) dyn_array_get_data (program_list, i));

		if (iprogram->user_number == -1) {
			continue;
		}

		flags = 0;
		if (iprogram->type == 1 || iprogram->type == 25 || iprogram->type == 31) { // SD, HD, UHD TV
			flags = flags | (1 << 3);
			flags = flags | (1 << 4);
			group = group_tv;
		} else if (iprogram->type == 2) {
			flags = flags | (1 << 4);
			group = group_radio;
		} else {
			continue;
		}

		if (iprogram->scrambled) {
			flags = flags | (1 << 0);
		}

		id = iprogram->channel->type << 24 | iprogram->channel->n << 8 | iprogram->n;

		//epg_id = (3 << 48) | (nid << 32) | (tid << 16) || sid;
		epg_id = id;

		utf8 = mydvb_text_to_utf8 (iprogram->service);
		aux = utf8 == NULL ? NULL : strdup (utf8);
		aux = replace (to_lower(aux), ' ','-');

		sprintf (group, "%s<channel nr=\"%d\" name=\"%s\" ID=\"%ld\" flags=\"%d\" EPGID=\"%ld\"><logo>icons/tv-logos-main/countries/spain/%s-es.png</logo></channel>"
				, group
				, iprogram->user_number == -1 ? num_channel++ : iprogram->user_number
				, utf8
				, id
				, flags
				, epg_id
				, aux
				);

		if (aux != NULL) free(aux);

		free (utf8);
	}

	sprintf (group_tv, "%s</group>", group_tv);
	sprintf (group_radio, "%s</group>", group_radio);

	sprintf (buf, "%s%s%s</root></channels>", buf, group_tv, group_radio);

	dyn_array_free (program_list);

	return buf;
}

/**
 * start: start timestamp (seconds since epoch, in UTC)
 * end: end timestamp (seconds since epoch, in UTC)
 */
void _dvbviewer_create_epg_eit (char *buf, MYDVB_EIT *eit, time_t start, time_t end) {

	DYN_ARRAY *entries;
	int len, i, j, k;

	MYDVB_EIT_ENTRY *eit_entry = NULL;
	mydvb_descriptor *descriptor;
	mydvb_short_event_descriptor *sed;
	mydvb_extended_event_descriptor *eed;
	mydvb_content_descriptor *cd;

	mydvb_ext_event_item *eei;

	char title[1024];
	char description[1024*4];
	int content = 0;

	char *text = NULL;
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

		if (t_utc < start || t_utc > end) {
			continue;
		}

		localtime_r(&t_utc, &stime);

		sprintf (buf, "%s<programme start=\"%04d%02d%02d%02d%02d%02d\""
				,buf
				,stime.tm_year+1900
				,stime.tm_mon+1
				,stime.tm_mday
				,stime.tm_hour
				,stime.tm_min
				,stime.tm_sec
				);
		stime.tm_sec += eit_entry->duration;
		mktime(&stime);
		sprintf (buf, "%s stop=\"%04d%02d%02d%02d%02d%02d\">"
				,buf
				,stime.tm_year+1900
				,stime.tm_mon+1
				,stime.tm_mday
				,stime.tm_hour
				,stime.tm_min
				,stime.tm_sec
				);

		sprintf (buf, "%s<eventid>%ld</eventid>"
				,buf
				,eit_entry->event_id
				);

		sprintf (title, "");
		sprintf (description, "");

		for (k=0; k < dyn_array_get_size(eit_entry->descriptors); k++) {

			descriptor = (mydvb_descriptor *) dyn_array_get_data(eit_entry->descriptors, k);

			if (descriptor->info.type == 0x4d) {

				sed = (mydvb_short_event_descriptor * ) descriptor;

				text = mydvb_text_to_utf8 (sed->event_name);
				if (text) {
					sprintf (title, STR_CONCAT
						,title
						,text
					);
					free (text);
				}

				text = mydvb_text_to_utf8 (sed->text);

				if (text) {
					sprintf (description, STR_CONCAT
						,description
						,text
					);
					free (text);
				}


			} else if (descriptor->info.type == 0x4e) {

				eed = (mydvb_extended_event_descriptor *) descriptor;

				for (j=0; j < dyn_array_get_size (eed->items); j++) {
					eei = (mydvb_ext_event_item *) dyn_array_get_data (eed->items, j);

					text = mydvb_text_to_utf8 (eei->item_description);
					if (text) {
						sprintf (description, "%s%s="
							,description
							,text
							);
						free (text);
					}

					text = mydvb_text_to_utf8 (eei->item_value);
					if (text) {
						sprintf (description, "%s%s\n"
							,description
							,text
							);
						free (text);
					}
				}

				text = mydvb_text_to_utf8 (eed->text);
				if (text) {
					sprintf (description, STR_CONCAT
						,description
						,text
						);
					free (text);
				}

			} else if (descriptor->info.type == 0x54) {

				cd = (mydvb_content_descriptor *) descriptor;

				for (j = 0; j < cd->num_contents; j++) {
					content = cd->content[j];
					break; // only the first one
				}

			}
		}

		sprintf (buf, "%s<titles><title>%s</title></titles>"
				,buf
				,title
		);

		if (strlen(description) > 0) {
			sprintf (buf, "%s<descriptions><description>%s</description></descriptions>"
					,buf
					,description
			);
		}

		sprintf (buf, "%s<content>%d</content>"
				,buf
				,content
				);

		sprintf (buf, "%s</programme>", buf);
	}
}

// <root>
// <programme start="" end="">
//    <eventid></eventid>
//	  <titles>
//		<title></title>
//	  </title>
//	  <descriptions>
//		<description></description>
//	  </descriptions>
//	  <events>
//	  	<event></event>
//	  </events>
//    <content></content>
// </programme>
// ...</root>
/**
 * start: start timestamp (seconds since epoch, in UTC)
 * end: end timestamp (seconds since epoch, in UTC)
 */
char *_dvbviewer_create_epg (MYDVB_ENGINE *engine, INFO_DVB *dvb, mydvb_tuner_type_t type, int channel, int service, time_t start, time_t end) {

	MYDVB *mydvb = NULL;
	MYDVB_PROGRAM *program = NULL;
	int i;

	char *buf = (char *) malloc (8192*32*sizeof(char));

	sprintf (buf, "<?xml version=\"1.0\" encoding=\"UTF-8\"?>");
	sprintf (buf, "%s<root>", buf);

	mydvb = mydvb_get_channel (engine, type, channel);

	if (mydvb) {

		program = mydvb_get_program_in_channel (mydvb, service);

		if (program != NULL) {
			//_dvbviewer_create_epg_eit (buf, program->eit, start, end);

			for (i = 0; i < 16 ; i++) {
				_dvbviewer_create_epg_eit (buf, program->eit_sched[i], start, end);
			}
		}
	}

	sprintf (buf, "%s</root>", buf);

	return buf;
}

char *_dvbviewer_timerlist (APP_INFO *app_info) {

	int i;
	PROG *p;

	char *buf = (char *) malloc (8192*32*sizeof(char));

	sprintf (buf, "<?xml version=\"1.0\" encoding=\"UTF-8\"?><root>");

	for (i=0; i < dyn_array_get_size (app_info->recorder->progs); i++) {
		p = *((PROG **) dyn_array_get_data (app_info->recorder->progs, i));

		if (p->status != 'W' && p->status != 'D' && p->status != 'R') {
			continue;
		}

		/*
		 *
		 * Date="%02d.%02d.%04d" day, month year
		 * Start="%02d:%02d:%02d" hour, min, sec
		 */
		struct tm t;

		time_t start_s = (time_t) (p->start / 1000);
		time_t end_s   = (time_t) (p->end / 1000);

		int d = (end_s - start_s) / 60;

		localtime_r(&start_s, &t);

		sprintf (buf, "%s<Timer Date=\"%02d.%02d.%04d\" Start=\"%02d:%02d:%02d\" Dur=\"%d\" PreEPG=\"0\" PostEPG=\"0\" Priority=\"50\" Enabled=\"%d\">"
				,buf
				,t.tm_mday, t.tm_mon + 1, t.tm_year + 1900
				,t.tm_hour, t.tm_min, t.tm_sec
				,d
				,p->status == 'D' ? 0 : 1
				);

		sprintf (buf, "%s<GUID>%ld</GUID><ID>%ld</ID><Descr>%s</Descr>"
				,buf
				,p->id
				,p->id
				,p->title
				);

		int channel_id = p->type << 24 | p->channel << 8 | p->service;
		sprintf (buf, "%s<Channel ID=\"%d\"></Channel>", buf
				,channel_id
				);

		if (p->status == 'R') {
			sprintf (buf, "%s<Recording>1</Recording>", buf);
		}

		sprintf (buf, "%s</Timer>", buf);
	}

	sprintf (buf, "%s</root>", buf);

	return buf;
}

void _dvbviewer_timeredit (APP_INFO *app_info, long id, time_t start, time_t end, mydvb_tuner_type_t type, int channel, int service, char *title, int enable) {

	PROG *prog = NULL;

	struct tm t;
	long long start_ms;
	long long end_ms;

	char filename[4096];

	gmtime_r (&end, &t);
	t.tm_isdst=-1;
	end_ms = (long long) mktime (&t) * 1000;

	gmtime_r (&start, &t);
	t.tm_isdst=-1;
	start_ms = (long long) mktime (&t) * 1000;

	char status = 'W';
	if (enable == 0) {
		status = 'D';
	} else {
		long long t_now = current_timestamp_ms ();
		if (t_now > end_ms) {
			status = 'T';
		}
	}

	if (id == -1) {

		prog = prog_new ();
		recorder_add (app_info->recorder, prog);

	} else {

		prog = recorder_get_by_id (app_info->recorder, id);
	}

	sprintf (filename, "%s", title);
	replace (filename, ' ','_');
	replace (filename, ':','_');

	sprintf (filename, "%s_%s_%d_%d_%04d%02d%02d%02d%02d%02d_%ld.ts"
			, filename
			, mydvb_tuner_type_table()[type]
			, channel
			, service
			, t.tm_year + 1900, t.tm_mon + 1, t.tm_mday, t.tm_hour, t.tm_min, t.tm_sec
			, prog->id);

	prog->start = start_ms;
	prog->end   = end_ms;
	prog->status = status;
	prog->type = type;
	prog->channel = channel;
	prog->service = service;
	if (prog->title) {
		free (prog->title);
	}
	prog->title = strdup (title);
	if (prog->file) {
		free (prog->file);
	}
	prog->file = strdup (filename);


	recorder_sort (app_info->recorder);

	// store it
	recorder_save (app_info->recorder);

	//recorder_log (app_info->recorder);

}

void _dvbviewer_timerdelete (APP_INFO *app_info, long id) {
	PROG *p = recorder_get_by_id (app_info->recorder, id);

	if (p == NULL) {
		return;
	}

	if (p->status == 'R') {

		p->end = current_timestamp_ms ();

	} else if (p->status == 'W' || p->status == 'D') {
		recorder_del_by_id (app_info->recorder, id, 1);
		recorder_save (app_info->recorder);
	}

}

char *_dvbviewer_recordings (APP_INFO *app_info) {

	int i;
	PROG *p;

	char *buf = (char *) malloc (8192*32*sizeof(char));

	sprintf (buf, "<?xml version=\"1.0\" encoding=\"UTF-8\"?><root>");

	for (i=0; i < dyn_array_get_size (app_info->recorder->progs); i++) {
		p = *((PROG **) dyn_array_get_data (app_info->recorder->progs, i));

		if (p->status != 'C') {
			continue;
		}

		/*
		 *
		 * start="%04d%02d%02d%02d%02d%02d" year, month, day, hour, min, sec
		 * duration="%02d%02d%02d" hour, min, sec
		 */
		struct tm t;

		time_t start_s = (time_t) (p->start / 1000);
		time_t end_s   = (time_t) (p->end / 1000);

		int d = end_s - start_s; // in total seconds

		localtime_r(&start_s, &t);

		sprintf (buf, "%s<recording id=\"%ld\" content=\"0\" start=\"%04d%02d%02d%02d%02d%02d\" duration=\"%02d%02d%02d\">"
				,buf
				,p->id
				,t.tm_year + 1900, t.tm_mon + 1, t.tm_mday, t.tm_hour, t.tm_min, t.tm_sec
				,d / 3600, (d / 60) % 60, d%60
				);

		sprintf (buf, "%s<title>%s</title><info></info><desc></desc>"
				,buf
				,p->title
				);

		INFO_PROGRAM *iprogram = info_dvb_find (app_info->info_dvb, p->type, p->channel, p->service);

		if (iprogram == NULL) {

			sprintf (buf, "%s<channel>unknown</channel>", buf);

		} else {
			char *utf8 = mydvb_text_to_utf8 (iprogram->service);

			sprintf (buf, "%s<channel>%s</channel>", buf
					,utf8
					);

			if (utf8) free (utf8);
		}

		sprintf (buf, "%s</recording>", buf);
	}

	sprintf (buf, "%s</root>", buf);

	return buf;
}

void _dvbviewer_recdelete (APP_INFO *app_info, long id, int delete_file) {
	recorder_del_by_id (app_info->recorder, id, delete_file);

	recorder_save (app_info->recorder);
}

// sprintf (body, "<?xml version=\"1.0\" encoding=\"UTF-8\"?>
// <status>
// <timercount>0</timercount><reccount>0</reccount><nexttimer>-1</nexttimer><nextrec>-1</nextrec><streamclientcount>0</streamclientcount><rtspclientcount>0</rtspclientcount><unicastclientcount>0</unicastclientcount><lastuiaccess>-1</lastuiaccess><standbyblock>1</standbyblock><tunercount>0</tunercount><streamtunercount>0</streamtunercount><rectunercount>0</rectunercount><epgudate>0</epgudate><rights>full</rights><recfiles>0</recfiles><recfolders></recfolders></status>");
char *_dvbviewer_status2 (APP_INFO *app_info) {

	int i;
	PROG *p;
	char filename[4096];
	struct stat f_stat;

	char *buf = (char *) malloc (8192*32*sizeof(char));

	int cnt_actives = 0;
	int cnt_ongoing_rec = 0;
	time_t nt_start = -1;
	int cnt_recs = 0;
	off_t folder_size = 0;

	time_t t_now_s = current_timestamp_ms () / 1000;

	for (i=0; i < dyn_array_get_size (app_info->recorder->progs); i++) {
		p = *((PROG **) dyn_array_get_data (app_info->recorder->progs, i));

		time_t start_s = (time_t) (p->start / 1000);
		time_t end_s   = (time_t) (p->end / 1000);

		time_t dif = start_s - t_now_s;

		if (p->status == 'W' || p->status == 'R') {
			cnt_actives ++;
			if (dif < nt_start || nt_start == -1) {
				nt_start = dif;
			}
		}
		if (p->status != 'R') {
			cnt_ongoing_rec ++;
		}
		if (p->status == 'C') {
			cnt_recs ++;

			sprintf (filename, "%s/%s", app_info->recorder->directory, p->file);
			if (stat (filename, &f_stat) == 0) {
				folder_size += f_stat.st_size;
			}
		}
	}

	int cnt_streamclient = 0;

	for (i = 0; i < dyn_array_get_size (app_info->receivers); i++) {
		STREAM_OUTPUT *so = *((STREAM_OUTPUT **) dyn_array_get_data (app_info->receivers, i));
		if (so->type == OUTPUT_TYPE_HTTP || so->type==OUTPUT_TYPE_RECORD) {
			cnt_streamclient ++;
		}

	}

	int cnt_tuner = 0;

	for (i = 0; i < dyn_array_get_size (app_info->engine.tuners); i++) {
		MYDVB_TUNE *tuner = *((MYDVB_TUNE **) dyn_array_get_data(app_info->engine.tuners, i));
		if (tuner->status != TUNER_STATUS_NOOP || tuner->references > 0) { // busy
			cnt_tuner ++;
		}
	}

	sprintf (buf, "<?xml version=\"1.0\" encoding=\"UTF-8\"?><status>");

	sprintf (buf, "%s<timercount>%d</timercount><reccount>%d</reccount><nexttimer>%ld</nexttimer><nextrec>%ld</nextrec><streamclientcount>%d</streamclientcount><rtspclientcount>0</rtspclientcount><unicastclientcount>0</unicastclientcount><lastuiaccess>-1</lastuiaccess><standbyblock>1</standbyblock><tunercount>%d</tunercount><streamtunercount>%d</streamtunercount><rectunercount>%d</rectunercount><epgudate>0</epgudate><rights>full</rights><recfiles>%d</recfiles>", buf
			,cnt_actives 		// timercount
			,cnt_ongoing_rec	// reccount
			,nt_start			// nexttimer
			,nt_start			// nextrec
			,cnt_streamclient	// streamclientcount
			,cnt_tuner			// tunercount
			,cnt_tuner			// treamtunercount
			,cnt_tuner			// rectunercount
			,cnt_recs			// recfiles
	);

	struct statvfs v_stat;
	statvfs(app_info->recorder->directory, &v_stat);

	off_t folder_free = v_stat.f_bfree * v_stat.f_frsize;

	sprintf (buf, "%s<recfolders><folder size=\"%lld\" free=\"%lld\">%s</folder></recfolders>"
			, buf
			, folder_size
			, folder_free
			, app_info->recorder->directory
			);

	sprintf (buf, "%s</status>", buf);

	return buf;
}

void _dvbviewer_response_xml (HTTP_RESPONSE *response, unsigned char *xml) {
	int body_len;

	body_len = strlen(xml);

	response->status=200;
	response->reason="OK";

	properties_add (response->headers, "Content-Type", "text/xml");
	properties_add_int (response->headers, "Content-Length", body_len);

	http_server_send (response, xml, body_len);
}

void _dvbviewer_response_txt (HTTP_RESPONSE *response, unsigned char *txt) {
	int body_len;

	body_len = strlen(txt);

	response->status=200;
	response->reason="OK";

	properties_add (response->headers, "Content-Type", "text/plain");
	properties_add_int (response->headers, "Content-Length", body_len);

	http_server_send (response, txt, body_len);
}

/**
 * return:
 *  2 if the handler has added the response to the receiver list
 * 	1 if the handler has fully completed the response
 * 	0 if the handler didn't complete the response
 *  -1 if error
 */
int dvbviewer_handler (HTTP_RESPONSE *response, APP_INFO *app_info) {
	HTTP_REQUEST *request = response->request;
	MYDVB_ENGINE *engine = &app_info->engine;

	int channel_id;

	int channel_type;
	int channel_num;
	int service_num;

	int r;

	unsigned char body[8192];

	if (strncmp ("/upnp/channelstream/", request->uri, 20)==0) {

		sscanf (request->uri, "/upnp/channelstream/%d.ts", &channel_id);

		channel_type = channel_id >> 24;
		channel_num = channel_id >> 8 & 0xffff;
		service_num = channel_id & 0x00ff;

		mydvb_log (MYDVB_LOG_LEVEL_INFO, "dvbviewer: program stream request %d/%d", channel_num, service_num);

		INFO_PROGRAM *ip = info_dvb_find (app_info->info_dvb, channel_type, channel_num, service_num);

		if (ip == NULL) {
			http_server_send_not_found (response);

			return 1;
		}

		MYDVB_TUNE *tuner = tuner_program (engine, ip);

		if (tuner) {
			response->status=200;
			response->reason="OK";

			properties_add (response->headers, "Content-Type", "video/mp2t");
			properties_add (response->headers, "Transfer-Encoding", "chunked");

			STREAM_OUTPUT *so = (STREAM_OUTPUT *) malloc (sizeof(STREAM_OUTPUT));
			dyn_array_add (app_info->receivers, &so);

			so->tuner = tuner;
			so->type = OUTPUT_TYPE_HTTP;
			so->u.http_output.response = response;

			return 2;

		} else {
			http_server_send_not_found (response);

			return 1;
		}

	} else if (strncmp ("/upnp/recordings/", request->uri, 17)==0) {

		// streaming of the recorded file

		long record_id = -1;
		char fn[4096];
		char crange[48];

		struct stat fstat;

		sscanf (request->uri, "/upnp/recordings/%ld.ts", &record_id);

		PROG *prog = recorder_get_by_id (app_info->recorder, record_id);
		if (prog == NULL) {
			http_server_send_not_found (response);

			return 1;

		}

		prog_get_file_path (prog, fn);

		if (stat (fn, &fstat) < 0) {
			http_server_send_not_found (response);

			return 1;
		}

		FILE *f = fopen (fn, "r");
		if (!f) {
			http_server_send_not_found (response);

			return 1;
		}

		// check Range header
		long start_pos = 0;
		char *range = properties_get (request->headers, "Range");
		if (range) {
			sscanf (range, "bytes=%ld-", &start_pos);
			sprintf (crange, "bytes %ld-%lld/%lld", start_pos, fstat.st_size, fstat.st_size);
			properties_add (response->headers, "Content-Range", crange);
		}

		fseek (f, start_pos, SEEK_SET);

		response->status=200;
		response->reason="OK";

		properties_add (response->headers, "Content-Type", "video/mp2t");
		properties_add (response->headers, "Transfer-Encoding", "chunked");
		//properties_add_long (response->headers, "Content-Length", fstat.st_size);


		STREAM_OUTPUT *so = (STREAM_OUTPUT *) malloc (sizeof(STREAM_OUTPUT));
		so->type = OUTPUT_TYPE_RECORD;
		so->tuner = NULL; // no tuner in record streaming
		so->u.record_output.response = response;
		so->u.record_output.f = f;

		so->u.record_output.listener_id = mydvb_register_ext_listener (engine, fileno(f), record_stream_callback, so);

		mydvb_log (MYDVB_LOG_LEVEL_INFO, "dvbviewer: starting transmission of recorded file %s of %lld bytes starting at %ld", fn, fstat.st_size, start_pos);

		return 2;

	} else {

		if (strcmp ("/api/version.html",request->uri)==0) {

			sprintf (body, "<?xml version=\"1.0\" encoding=\"UTF-8\"?><version iver=\"%ld\">DVBTrans 1.0.0 DoraTv</version>", (long) 7 << 24 | 2 << 16 | 5 << 8 | 0);

			_dvbviewer_response_xml (response, body);

		} else if (strcmp ("/api/status2.html",request->uri)==0) {

			mydvb_log (MYDVB_LOG_LEVEL_INFO,"dvbviewer: status2 request");

			char *xml_status2 = _dvbviewer_status2 (app_info);

			_dvbviewer_response_xml (response, xml_status2);

			free (xml_status2);
			xml_status2 = NULL;

		} else if (strcmp ("/api/getconfigfile.html",request->uri)==0) {

			sprintf (body, "<?xml version=\"1.0\" encoding=\"UTF-8\"?><root><section name=\"other\"></section></root>");

			_dvbviewer_response_xml (response, body);

		} else if (strcmp ("/api/searchlist.html",request->uri)==0) {

			sprintf (body, "<?xml version=\"1.0\" encoding=\"UTF-8\"?><root><Search></Search></root>");

			_dvbviewer_response_xml (response, body);

		} else if (strcmp ("/api/recordings.html",request->uri)==0) {

			// Parameters
			// utf8=1
			// images=1

			char *xml_recordings = _dvbviewer_recordings (app_info);

			_dvbviewer_response_xml (response, xml_recordings);

			free (xml_recordings);
			xml_recordings = NULL;

		} else if (strcmp ("/api/recdelete.html",request->uri)==0) {

			// Parameters
			// recid=6
			// delfile=1

			long id = properties_get_long (request->parameters, "recid");
			int delfile = properties_get_int (request->parameters, "delfile");

			_dvbviewer_recdelete (app_info, id, delfile);

			sprintf (body, "<?xml version=\"1.0\" encoding=\"UTF-8\"?><root>ok</root>");

			_dvbviewer_response_xml (response, body);

		} else if (strcmp ("/api/epg.html",request->uri)==0) {

			// Parameters:
			// lvl=2
			// channel=1441794
			// start=45389.744838
			// end=45393.744838

			channel_id = properties_get_int (request->parameters, "channel");

			channel_type = channel_id >> 24;
			channel_num = channel_id >> 8 & 0xffff;
			service_num = channel_id & 0x00ff;

			// start and end are in UTC
			double start = properties_get_double (request->parameters, "start");
			double end 	 = properties_get_double (request->parameters, "end");

			if (start == 0 || end == 0) {
				sprintf (body, "<?xml version=\"1.0\" encoding=\"UTF-8\"?><root></root>");

				_dvbviewer_response_xml (response, body);

			} else {
				// convert the decimal format of dvbviewer to timestamp (UTC in seconds)
				start = (start - 25569) * 86400.0;
				end = (end - 25569) * 86400.0;
			}

			char *xml_epg = _dvbviewer_create_epg (engine, app_info->info_dvb, channel_type, channel_num, service_num, (time_t) start, (time_t) end);

			_dvbviewer_response_xml (response, xml_epg);

			free (xml_epg);
			xml_epg = NULL;


		} else if (strcmp ("/api/getchannelsxml.html",request->uri)==0) {

			char *xmlChannelList = _dvbviewer_create_channel_list (app_info->info_dvb);

			_dvbviewer_response_xml (response, xmlChannelList);

			free (xmlChannelList);

		} else if (strncmp ("/icons/tv-logos-main/",request->uri, 21)==0) {

			http_server_send_file (response, request->uri);

		} else if (strcmp ("/api/timerlist.html",request->uri)==0) {

			// parameters
			// utf8=2

			char *xml_timerlist = _dvbviewer_timerlist (app_info);

			_dvbviewer_response_xml (response, xml_timerlist);

			free (xml_timerlist);
			xml_timerlist = NULL;

		} else if (strcmp ("/api/timeradd.html",request->uri)==0
				|| strcmp ("/api/timeredit.html",request->uri)==0) {

			// Parameters
			// encoding=255
			// ch=1441797
			// dor=45400
			// start=1320
			// stop=1365
			// pre=0
			// post=0
			// days=-------
			// enable=1
			// title=LA%20MATEMATICA%20DEL%20ESPEJO (url encoded)
			// folder=Auto
			// id=N (only for timeredit.html)

			long id = -1;
			if (properties_has_key (request->parameters, "id")) {
				id = properties_get_long (request->parameters, "id");
			}

			long dor 	= properties_get_long (request->parameters, "dor");

			time_t start = properties_get_long (request->parameters, "start");
			time_t end 	= properties_get_long (request->parameters, "stop");

			channel_id = properties_get_int (request->parameters, "ch");

			int enable = properties_get_int (request->parameters, "enable");

			char *title = properties_get (request->parameters, "title");
			title = url_decode (title);

			channel_type = channel_id >> 24;
			channel_num = channel_id >> 8 & 0xffff;
			service_num = channel_id & 0x00ff;

			dor 	= (dor - 25569) * 86400;
			start 	= dor + 60*start; 	// in s
			end 	= dor + 60*end;	// in s

			_dvbviewer_timeredit (app_info, id, start, end, channel_type, channel_num, service_num, title, enable);

			if (title) {
				free (title);
				title = NULL;
			}

			sprintf (body, "<?xml version=\"1.0\" encoding=\"UTF-8\"?><root>ok</root>");

			_dvbviewer_response_xml (response, body);

		} else if (strcmp ("/api/timerdelete.html",request->uri)==0) {

			// Parameters:
			// id: identifier of the recording
			long id = properties_get_long (request->parameters, "id");

			_dvbviewer_timerdelete (app_info, id);

			sprintf (body, "<?xml version=\"1.0\" encoding=\"UTF-8\"?><root>ok</root>");

			_dvbviewer_response_xml (response, body);

		} else if (strcmp ("/api/store.html",request->uri)==0) {

			// TODO: pending
			// Parameters:
			// action=read
			// sec=kodi-bfa5-4ac6-8bc2-profile00

			char *sec 		= properties_get (request->parameters, "sec");
			char *action 	= properties_get (request->parameters, "action");

			//_dvbviewer_timerdelete (app_info, id);

			sprintf (body, "");

			_dvbviewer_response_txt (response, body);

		} else {

			mydvb_log (MYDVB_LOG_LEVEL_ERROR, "dvbviewer unknown request. Header line: %s %s %s", request->method, request->uri, request->version);
			for (int pos = 0 ; pos < properties_size (request->headers); pos++) {
				property *p = properties_get_at (request->headers, pos);
				mydvb_log (MYDVB_LOG_LEVEL_ERROR, "--Header %s=%s", p->key, p->value);
			}
			for (int pos = 0 ; pos < properties_size (request->parameters); pos++) {
				property *p = properties_get_at (request->parameters, pos);
				mydvb_log (MYDVB_LOG_LEVEL_ERROR, "--Parameter %s=%s", p->key, p->value);
			}


			return 0;
		}

		return 1;
	}
}
