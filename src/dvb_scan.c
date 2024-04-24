/* compilar con:

gcc -I/usr/src/linux-headers-3.2.0-4-common -I.. `xml2-config --cflags` -c -o dvb_scan.o dvb_scan.c
gcc -lpthread -o dvb_scan dvb_scan.o `xml2-config --libs` ../libmydvb.a

*/

#include <stdio.h>

#include "mydvb.h"
#include "info_dvb.h"



void handler (int e, INFO_CHANNEL *ichannel, void *data) {
	if (e == INFO_DVB_EVENT_TUNE_START) {
		printf ("Buscando programas en canal %d\n", ichannel->n);
	} else if (e == INFO_DVB_EVENT_CHANNEL_ADDED) {
		printf ("Agregado canal %d\n", ichannel->n);
	} 
}

int main (int argc, char *args[]) {
	MYDVB *mydvb;
	MYDVB_LIST *dvb_list;
	INFO_DVB *dvb_info;
	MYDVB_TUNE_PARAMETER tune_param;

	dvb_list = mydvb_list_new ();

	mydvb = mydvb_list_get_dvbt (dvb_list);
	if (mydvb!=NULL) {
		mydvb_init (mydvb, NULL);
		
		/* init tune parameters for dvb-t */
		tune_param.param_t.f_start  = 474000000; // + 8000000*13; // 474000000;
		tune_param.param_t.f_end    = 858000000;
		tune_param.param_t.f_step   =   8000000; // 8MHz bandwidth
		tune_param.param_t.callback =NULL;

		dvb_info = mydvb_tune_scan (mydvb, &tune_param, handler, NULL);

		if (dvb_info != NULL) {
			info_dvb_save ("/tmp/dvb_scan.txt", dvb_info);
			info_dvb_save_channels_conf ("/tmp/channels.conf", dvb_info);
		}

		mydvb_end (mydvb);
	}

	mydvb_list_free (dvb_list);	

	return 0;
}
