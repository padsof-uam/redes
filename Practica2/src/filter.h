#ifndef FILTER_H
#define FILTER_H

#include <stdio.h>
#include <stdlib.h>
#include <inttypes.h>
#include <pcap.h>
#include <string.h>
#include <netinet/in.h>
#include <signal.h>
#include <time.h>
#include <stdarg.h>
#include "packet_extractor.h"

/************************ Definicion de constantes ***********************/
#define ETH_ALEN      6      /* Tamano de direccion ethernet             */
#define ETH_HLEN      14     /* Tamano de cabecera ethernet              */
#define ETH_TLEN      2      /* Tamano del campo tipo ethernet           */
#define TCP 6                /* Protocolo TCP                            */
#define UDP 17               /* Protocolo UDP                            */
#define ETH_FRAME_MAX 1514   /* Tamano maximo trama ethernet (sin CRC)   */
#define ETH_FRAME_MIN 60     /* Tamano minimo trama ethernet (sin CRC)   */

#define CHECKFOR(what) if(what != -1 && p_##what != what) return 1;


typedef struct 
{
    u_int32_t ip_src;
    u_int32_t ip_dst;
    u_int32_t port_src;
    u_int32_t port_dst;  
}args;

u_int8_t analizarPaquete(u_int8_t *paquete, struct pcap_pkthdr *cabecera, args * filter_values);

uint32_t ip_fromstr(const char* ipstr);

static const char* proto_informer(const uint32_t* values);

short arg_parser(const int argc, const char **argv,args * filter_values);
short filter(u_int8_t* packet, uint32_t eth_type,args* filter_values);

short _filter(u_int8_t* packet, uint32_t eth_type, uint32_t ip_dst, uint32_t ip_src, uint32_t port_dst, uint32_t port_src);


#endif