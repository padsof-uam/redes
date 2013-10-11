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
#define TCP 6                /* Protocolo TCP                            */
#define UDP 17               /* Protocolo UDP                            */
#define ETH_FRAME_MAX 1514   /* Tamano maximo trama ethernet (sin CRC)   */
#define ETH_FRAME_MIN 60     /* Tamano minimo trama ethernet (sin CRC)   */

/* Tamano maximo y minimo de los datos de una trama ethernet             */
#define ETH_DATA_MAX  (ETH_FRAME_MAX - ETH_HLEN)
#define ETH_DATA_MIN  (ETH_FRAME_MIN - ETH_HLEN)
#define OK 0
#define ERROR 1

#define IP(a,b,c,d) (a << 3 + b << 2 + c << 1 + d)

u_int8_t analizarPaquete(u_int8_t *, struct pcap_pkthdr *, u_int64_t);
void handleSignal(int nsignal);

pcap_t *descr;
u_int64_t cont = 0;

void handleSignal(int nsignal)
{
    printf("Control-C pulsado (%" PRIu64 ")\n", cont);
    pcap_close(descr);
    exit(OK);
}

typedef struct 
{
    u_int8_t ip_src[4];
    u_int8_t ip_dst[4];
    u_int16_t port_src;
    u_int16_t port_dst;  
}args;


short arg_parser(int argc, char **argv,args*filter_values);
int main(int argc, char **argv)
{
    char errbuf[PCAP_ERRBUF_SIZE];
    u_int8_t *paquete;
    struct pcap_pkthdr *cabecera;
    u_int8_t retorno;
    int capture_retval;
    int retval = OK;
    args filter_values;

    uint32_t a =ip_fromstr("192.168.126.128");

    printf("%d\n", a);

    if (arg_parser(argc, argv,&filter_values) == 1)
        printf("Error en los argumentos introducidos\n");


    if (signal(SIGINT, handleSignal) == SIG_ERR)
    {
        printf("Error: Fallo al capturar la senal SIGINT.\n");
        exit(ERROR);
    }

    if (argc != 2)
    {
        printf("Ejecucion: %s /ruta/captura_pcap\n", argv[0]);
        exit(ERROR);
    }

    if ( (descr = pcap_open_offline(argv[1], errbuf)) == NULL)
    {
        printf("Error: pcap_open_offline(): File: %s, %s %s %d.\n", argv[1], errbuf, __FILE__, __LINE__);
        exit(ERROR);
    }

    while ((capture_retval = pcap_next_ex(descr, &cabecera, (const u_char **) (&paquete))) == 1)
    {
        cont++;

        if ((retorno = analizarPaquete(paquete, cabecera, cont)) != OK)
        {
            printf("Error al analizar el paquete %" PRIu64 "; %s %d.\n", cont, __FILE__, __LINE__);
            exit(retorno);
        }
    }

    if (capture_retval == -1)
    {
        printf("Error: pcap_open_offline(): File: %s, %s %s %d.\n", argv[1], errbuf, __FILE__, __LINE__);
        pcap_perror(descr, "pcap error:");

        retval = ERROR;
    }
    else // PCAP_ERROR_BREAK es la otra salida posible, hemos llegado a final de archivo.
    {
        printf("No hay mas paquetes.\n Capturados %" PRIu64 " paquetes.\n\n", cont);
    }

    pcap_close(descr);

    return retval;
}

static const char* proto_informer(const uint32_t* values)
{
    switch (values[0])
    {
	    case TCP:
	        return "TCP";
	    case UDP:
	        return "UDP";
	    default:
	        return "Unknown";
    }
}

#define CHECKFOR(what) if(what != -1 && p_##what != what) return 1;

short arg_parser(int argc, char **argv,args*filter_values){


}
short filter(const u_int8_t* packet, uint32_t eth_type, uint32_t ip_dst, uint32_t ip_src, uint32_t port_dst, uint32_t port_src)
{
	uint32_t p_eth_type, p_protocol, p_ip_dst, p_ip_src, p_port_dst, p_port_src;
	uint32_t ip_header_size;

	extract(packet, ETH_ALEN * 2, 16, 1, &p_eth_type);

	packet += ETH_ALEN * 2 + ETH_TLEN; // ETH header end.

	extract_offset(packet, 0, 4, 1, 4, &ip_header_size);

    extract(packet, 9, 1, 8, &p_protocol);
    extract(packet, 12, 1, 32, &p_ip_src);
    extract(packet, 16, 1, 32, &p_ip_dst);


	packet += ip_header_size * 4; // IP header end.

	extract(packet, 0, 1, 16, &p_port_src);
	extract(packet, 2, 1, 16, &p_port_dst);

    if(p_protocol != UDP && p_protocol != TCP)
        return 1;

    CHECKFOR(eth_type);
	CHECKFOR(ip_src);
	CHECKFOR(ip_dst);
	CHECKFOR(port_src);
	CHECKFOR(port_dst);

	return 0;
}

u_int8_t analizarPaquete(u_int8_t *paquete, struct pcap_pkthdr *cabecera, u_int64_t cont)
{
    uint32_t eth_type;
    uint32_t ip_header_size;
    uint32_t protocol;

    uint32_t ip_src = ip_fromstr("192.168.126.1");
    uint32_t ip_dst = ip_fromstr("192.168.126.255");
    filter(paquete, 2048, ip_src,ip_dst, 17500, 17500);

    print_packet_field(paquete, "MAC destino", 0, 0, 8, ETH_ALEN, HEX);
    print_packet_field(paquete, "MAC origen", ETH_ALEN, 0, 8, ETH_ALEN, HEX);
    print_packet_field(paquete, "Tipo ETH", ETH_ALEN * 2, 0, 16, 1, HEX);
    
    extract(paquete, ETH_ALEN * 2, 1, 16, &eth_type);

    if (eth_type != 2048)
    {
        printf("El tipo ethernet no es válido\n\n");
        return OK;
    }

    //Fin encapsulamiento Ethernet
    paquete += ETH_ALEN * 2 + ETH_TLEN;
    //IP: version IP, longitud de cabecera, longitud total, posicion, tiempo de vida, protocolo, y ambas direcciones IP
    print_packet_field(paquete, "Versión IP", 0, 0, 4, 1, DEC);
    print_packet_field(paquete, "Long. header", 0, 4, 4, 1, DEC);
    print_packet_field(paquete, "Longitud", 2, 0, 16, 1, DEC);
    print_packet_field(paquete, "Posición", 6, 3, 13, 1, DEC);
    print_packet_field(paquete, "TTL\t", 8, 0, 8, 1, DEC);
    print_packet_field_i(paquete, "Protocolo", 9, 0, 8, 1, DEC, proto_informer);
    print_packet_field(paquete, "IP origen", 12, 0, 8, 4, DEC);
    print_packet_field(paquete, "IP destino", 16, 0, 8, 4, DEC);

    extract(paquete, 9, 1, 8, &protocol);
    extract_offset(paquete, 0, 4, 1, 4, &ip_header_size);

    if(protocol != TCP && protocol != UDP)
    {
    	printf("Protocolo inválido.\n");
    	return OK;
    }

    paquete += ip_header_size * 4;

    print_packet_field(paquete, "Puerto origen", 0, 0, 16, 1, DEC);
    print_packet_field(paquete, "Puerto destino", 2, 0, 16, 1, DEC);

    if(protocol == UDP)
    {
    	print_packet_field(paquete, "Long. UDP", 4, 0, 16, 1, DEC);
    }

    printf("\n");

    return OK;
}
