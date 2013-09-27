/***************************************************************************
Ejemplo pcap_next.pcap
gcc -o EjemploPcapNext EjemploPcapNext.c -lpcap
***************************************************************************/

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdio.h>
#include <stdlib.h>

#include <pcap.h>
#include <string.h>
#include <netinet/in.h>
#include <linux/udp.h>
#include <linux/tcp.h>
#include <signal.h>
#include <time.h>
#define OK 0
#define ERROR 1

pcap_t* descr;

volatile sig_atomic_t ctr_pressed = 0;

void handle(int nsignal){
	printf("Control C pulsado\n");
	ctr_pressed = 1;
 }

int main(int argc, char **argv)
{
	int i;
	char errbuf[PCAP_ERRBUF_SIZE];
	u_char *packet;
	struct pcap_pkthdr h;
	
	if(signal(SIGINT,handle)==SIG_ERR){
		printf("Error: Fallo al capturar la senal SIGINT.\n");
		exit(ERROR);
	}
	
   	if ((descr = pcap_open_live("eth0",10,0, 0, errbuf)) == NULL){
		printf("Error: pcap_open_live(): %s %s %d.\n",errbuf,__FILE__,__LINE__);
		exit(ERROR);
	}
	i=0;
	while(!ctr_pressed){
		if ((packet = (u_int8_t*) pcap_next(descr,&h))==NULL){
			printf("Error al capturar el paquete %s %d.\n",__FILE__,__LINE__);
			exit(ERROR);
		}
		printf("Nuevo paquete recibido el %s\n",ctime((const time_t*)&h.ts.tv_sec));
		i++;
	}
	
	pcap_close(descr);

  return OK;
}

