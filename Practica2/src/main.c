/***************************************************************************
Ejemplo practica2.c
gcc -o practica2 practica2.c -lpcap
***************************************************************************/

#include <stdio.h>
#include <stdlib.h>

#include <pcap.h>
#include <string.h>
#include <netinet/in.h>
#include <linux/udp.h>
#include <linux/tcp.h>
#include <signal.h>
#include <time.h>

/************************ Definicion de constantes ***********************/
#define ETH_ALEN      6      /* Tamano de direccion ethernet             */
#define ETH_HLEN      14     /* Tamano de cabecera ethernet              */
#define ETH_TLEN      2      /* Tamano del campo tipo ethernet           */
#define ETH_FRAME_MAX 1514   /* Tamano maximo trama ethernet (sin CRC)   */
#define ETH_FRAME_MIN 60     /* Tamano minimo trama ethernet (sin CRC)   */

/* Tamano maximo y minimo de los datos de una trama ethernet             */
#define ETH_DATA_MAX  (ETH_FRAME_MAX - ETH_HLEN)
#define ETH_DATA_MIN  (ETH_FRAME_MIN - ETH_HLEN)
#define OK 0
#define ERROR 1

u_int8_t analizarPaquete(u_int8_t*,struct pcap_pkthdr*,u_int64_t);
void handleSignal(int nsignal);

pcap_t* descr;
u_int64_t cont=1;

void handleSignal(int nsignal){
	printf("Control C pulsado (%lu)\n", cont);
	pcap_close(descr);
	exit(OK);
}

int main(int argc, char **argv)
{
	
	char errbuf[PCAP_ERRBUF_SIZE];
	u_int8_t* paquete;
	struct pcap_pkthdr cabecera;
	u_int8_t retorno;
	
	if(signal(SIGINT,handleSignal)==SIG_ERR){
		printf("Error: Fallo al capturar la senal SIGINT.\n");
		exit(ERROR);
	}

	if(argc!=2){
		printf("Ejecucion: %s /ruta/captura_pcap\n",argv[0]);
		exit(ERROR);
	}

   	if ( (descr = pcap_open_offline(argv[1], errbuf)) == NULL){
		printf("Error: pcap_open_offline(): File: %s, %s %s %d.\n", argv[1], errbuf,__FILE__,__LINE__);
		exit(ERROR);
	}

	if ( (paquete = (u_int8_t*) pcap_next(descr,&cabecera)) ==NULL){
			printf("Error al capturar al capturar trafico; %s %d.\n",__FILE__, __LINE__);
			exit(ERROR);
	}else{
		if( (retorno=analizarPaquete(paquete, &cabecera,cont))==ERROR){
			printf("Error al analizar el primer paquete; %s %d.\n",__FILE__, __LINE__);
			exit(ERROR);
		}
	}

	while( (paquete = (u_int8_t*) pcap_next(descr,&cabecera)) !=NULL){
		cont++;

		if( (retorno=analizarPaquete(paquete, &cabecera,cont)) ==ERROR){
			printf("Error al analizar el paquete %lu; %s %d.\n",__FILE__, __LINE__);
			exit(ERROR);
		}
	}

	printf("No hay mas paquetes (%lu).\n\n",cont, __FILE__, __LINE__);
	pcap_close(descr);

	return OK;
}

u_int8_t analizarPaquete(u_int8_t* paquete,struct pcap_pkthdr* cabecera,u_int64_t cont){
	
	int i=0;
	u_int8_t* paquete_bck=paquete;

	printf("Direccion ETH destino= ");	
	printf("%02X",paquete[i]);
	for (i=1;i<ETH_ALEN;i++){
		printf(":%02X",paquete[i]);
	}
	printf("\n");
	printf("Direccion ETH origen = ");	
	printf("%02X",paquete[i]);
	paquete+=ETH_ALEN;
	for (i=1;i<ETH_ALEN;i++){
		printf(":%02X",paquete[i]);
	}
	printf("\n");

	//paquete+=ETH_ALEN;
	// .....
	// .....
	// .....

	printf("\n\n");
	return OK;
}
