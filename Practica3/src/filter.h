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
#include "packet_parser.h"

typedef struct 
{
    int ip_src;
    int ip_dst;
    int port_src;
    int port_dst; 
} filter_params;


void ip_tostr(uint32_t ip, char* ipstr);

/**
 * Converts an ip from string to uint32_t.
 * @param  ipstr          The ip as string to be converted.
 * @return                The ip as an uint23_t.
 */
uint32_t ip_fromstr(const char* ipstr);

/**
 * Fills the struct filter (given as a parameter) with the arguments given.
 * @param  argc				Number of arguments given.
 * @param  argv				Array with all the arguments.
 * @param  filter			The struct to be filled.
 * @return					OK if filled correctly, ERR if some error happened.
 */
short arg_parser(const int argc, const char **argv, filter_params *args);

/**
 * Analyzes a packet contents.
 * @param  paquete  Packet.
 * @param  cabecera Header
 * @param  filter   Filter values
 * @param  cont     Packet count
 * @return          OK or ERR if there was an error.
 */
int analizarPaquete(u_int8_t *paquete, struct pcap_pkthdr *cabecera, filter_params* args,int cont);

/**
 * Reads the packet and compares it with the filter parameters.
 * @param  packet         Packet, given as an array of 1 byte values.
 * @param  eth_type		  The ethernet type to filter by.
 * @param  filter  		  The struct with all the filter parameters.          
 * @return                0 if the packet passes all the filters, 1 if it's rejected.
 */
short filter(u_int8_t* packet, uint32_t eth_type,filter_params* args);

#endif
