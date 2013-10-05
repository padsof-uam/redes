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

#include "packet_extractor.h"

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
	printf("Control-C pulsado (%" PRIu64 ")\n", cont);
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

u_int8_t analizarPaquete(u_int8_t* paquete, struct pcap_pkthdr* cabecera,u_int64_t cont)
{	
	struct packet_val eth_type;
	eth_type.size = 16;

	print_packet_field(paquete, "MAC destino", 0, 0, 8, ETH_ALEN, HEX);
	print_packet_field(paquete, "MAC origen", ETH_ALEN, 0, 8, ETH_ALEN, HEX);

	extract(paquete, ETH_ALEN * 2 * 8, 1, &eth_type);
	printf("Tipo ETH:\t");
	printf_val(&eth_type, 1, HEX);
	printf("\n");

	if (eth_type.v.uint16[0] != 2048)
	{
		printf("El tipo ethernet no es válido\n\n");
		return OK;
	}

	//Fin encapsulamiento Ethernet
	paquete += ETH_ALEN * 2 + ETH_TLEN;
	//IP: version IP, longitud de cabecera, longitud total, posicion, tiempo de vida, protocolo, y ambas direcciones IP
	print_packet_field(paquete, "Versión IP", 0, 0, 4, 1, DEC);
	print_packet_field(paquete, "Longitud", 2, 0, 16, 1, DEC);

	printf("\n");
	return OK;
}
