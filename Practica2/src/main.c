/***************************************************************************
Ejemplo practica2.c
gcc -o practica2 practica2.c -lpcap
***************************************************************************/

#include <stdio.h>
#include <stdlib.h>
#include <inttypes.h>
#include <pcap.h>
#include <string.h>
#include <netinet/in.h>
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
u_int64_t cont = 0;

void handleSignal(int nsignal){
	printf("Control C pulsado (%" PRIu64 ")\n", cont);
	pcap_close(descr);
	exit(OK);
}

int main(int argc, char **argv)
{
	char errbuf[PCAP_ERRBUF_SIZE];
	u_int8_t* paquete;
	struct pcap_pkthdr* cabecera;
	u_int8_t retorno;
	int capture_retval;
	int retval = OK;

	if(signal(SIGINT,handleSignal)==SIG_ERR)
	{
		printf("Error: Fallo al capturar la senal SIGINT.\n");
		exit(ERROR);
	}

	if(argc != 2)
	{
		printf("Ejecucion: %s /ruta/captura_pcap\n",argv[0]);
		exit(ERROR);
	}

   	if ( (descr = pcap_open_offline(argv[1], errbuf)) == NULL)
   	{
		printf("Error: pcap_open_offline(): File: %s, %s %s %d.\n", argv[1], errbuf,__FILE__,__LINE__);
		exit(ERROR);
	}

	while((capture_retval = pcap_next_ex(descr, &cabecera, (const u_char **) (&paquete))) == 1)
	{
		cont++;

		if((retorno = analizarPaquete(paquete, cabecera, cont)) != OK){
			printf("Error al analizar el paquete %" PRIu64 "; %s %d.\n", cont, __FILE__, __LINE__);
			exit(retorno);
		}
	}

	if(capture_retval == -1)
	{
		printf("Error: pcap_open_offline(): File: %s, %s %s %d.\n", argv[1], errbuf,__FILE__,__LINE__);
		pcap_perror(descr, "pcap error:");

		retval = ERROR;
	}
	else // PCAP_ERROR_BREAK es la otra salida posible, hemos llegado a final de archivo.
	{
		printf("No hay mas paquetes.\n Capturados %" PRIu64 " paquetes.\n\n",cont);
	}

	pcap_close(descr);

	return retval;
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
