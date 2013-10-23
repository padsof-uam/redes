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
#define NO_FILE -20

#define CHECKFOR(what) if(what != -1 && p_##what != what) return 1;


typedef struct 
{
    int ip_src;
    int ip_dst;
    int port_src;
    int port_dst; 
} args;


/**
 * Converts an ip from string to uint32_t.
 * @param  ipstr          The ip as string to be converted.
 * @return                The ip as an uint23_t.
 */

uint32_t ip_fromstr(const char* ipstr);

/**
 * Fills the strcut filter_values (given as a parameter) with the arguments given.
 * @param  argc				Number of arguments given.
 * @param  argv				Array with all the arguments.
 * @param  filter_values	The struct to be filled.
 * @return					OK if filled correctly, ERR if some error happened.
 */
short arg_parser(const int argc, const char **argv, args *filter_values);

/* Guille xD wtf is cabecera*/

int analizarPaquete(u_int8_t *paquete, struct pcap_pkthdr *cabecera, args* filter_values,int cont);

/**
 * Reads the packet and compares it with the filter_values.
 * @param  packet         Packet, given as an array of 1 byte values.
 * @param  eth_type		  The ethernet type to filter by.
 * @param  filter_values  The struct with all the information to filter by.          
 * @return                0 if the packet checks all the filters, others if not.
 */
short filter(u_int8_t* packet, uint32_t eth_type,args* filter_values);

/**
 * Auxiliary function to filter by.
 * @param  packet         Packet, given as an array of 1 byte values.
 * @param  eth_type		  The ethernet type to filter. 
 * @param  ip_dest		  The destiny ip adrress to be filtered by.
 * @param  ip_src		  The source ip adrress to be filtered by.
 * @param  port_dst		  The destiny port to be filtered by.
 * @param  port_src		  The source port  to be filtered by.
 * @return                0 if OK, negative value if error.
 */
short _filter(u_int8_t* packet, uint32_t eth_type, uint32_t ip_dst, uint32_t ip_src, uint32_t port_dst, uint32_t port_src);


#endif
