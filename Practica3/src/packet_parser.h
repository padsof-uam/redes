#ifndef PACKET_EXTRACTOR_H
#define PACKET_EXTRACTOR_H

#ifndef __STDC_FORMAT_MACROS
#define __STDC_FORMAT_MACROS 1
#endif

#include <cstdio>
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
#define TCP 6                /* Protocolo TCP                            */
#define UDP 17               /* Protocolo UDP                            */
#define ETH_FRAME_MAX 1514   /* Tamano maximo trama ethernet (sin CRC)   */
#define ETH_FRAME_MIN 60     /* Tamano minimo trama ethernet (sin CRC)   */
#define NO_FILE -20
#define ETH_TYPE_IP 0x0800

#define MAX_VAL_LEN 20
#define ERR_UNSUPPORTED_SIZE -10
#define ERR_UNSUPPORTED_FORMAT -11

/* Tamano maximo y minimo de los datos de una trama ethernet             */
#define ETH_DATA_MAX  (ETH_FRAME_MAX - ETH_HLEN)
#define ETH_DATA_MIN  (ETH_FRAME_MIN - ETH_HLEN)
#define OK 0
#define ERROR -1

#define TOBYTESIZE(bit) ((bit) / 8 ? (bit) / 8 : 1)

typedef enum {
	HEX, DEC
} format_type;

struct packet_val
{
	short size;
	short num_values;
	union 
	{
		uint8_t uint8[MAX_VAL_LEN];
		uint16_t uint16[MAX_VAL_LEN];
		uint32_t uint32[MAX_VAL_LEN];
	} v;
};

typedef const char* (*informer)(const uint32_t* value);

/**
 * Converts an IP (X.X.X.X) to its numeric representation in four bytes.
 * @param  ipstr String
 * @return       Numeric representation.
 */
uint32_t ip_fromstr(const char* ipstr);

/**
 * Extracts one or more numbers from a packet.
 * @param  packet         Packet, given as an array of 1 byte values.
 * @param  byte_start     Byte offset where the value starts.
 * @param  num            Number of values to extract. 
 * @param  bit_block_size Size of each value, in bits.
 * @param  array          Array where the values will be saved.
 * @return                0 if OK, negative value if error.
 */
int extract(const uint8_t* packet, int byte_start, int num, int bit_block_size, u_int32_t* array);

/**
 * Extracts one or more numbers from a packet when the value is not byte-aligned.
 *
 * For example, if you want to extract a number starting in the 10th bit of the packet, 
 * 	you will set byte_start = 1 and bit_offset = 2 (byte_start * 8 + bit_offset) = 10 bits, where
 * 	the value starts.
 * @param  packet         Packet, given as an array of 1 byte values.
 * @param  bit_offset	  Bit offset where the value starts.
 * @param  byte_start     Byte offset where the value starts.
 * @param  num            Number of values to extract. 
 * @param  bit_block_size Size of each value, in bits.
 * @param  array          Array where the values will be saved.
 * @return                0 if OK, negative value if error.
 */
int extract_offset(const uint8_t* packet, int byte_start, int bit_offset, int num, int bit_block_size, uint32_t* array);

/**
 * Print an array of values.
 * @param  values    Values.
 * @param  length    Length of the array.
 * @param  type      Format (HEX/DEC)
 * @param  byte_size Size (bytes) of each value. Important when printing HEX.
 * @return           0 if OK, <0 if error.
 */
int printf_val(const u_int32_t* values, int length, format_type type, int byte_size);

/**
 * Prints a given field of the packet.
 * @param  packet         Packet.
 * @param  title          Title for the field.
 * @param  byte_start     Byte start position.
 * @param  bit_offset     Bit offset.
 * @param  bit_block_size Size of each value (bits)
 * @param  length         Number of values to extract.
 * @param  format         Format to print the value.
 * @return                0 if OK, < 0 if error.
 */
int print_packet_field(const uint8_t* packet, const char* title, int byte_start, int bit_offset, int bit_block_size, int length, format_type format);

/**
 * Prints a given field of the packet with additional information
 * @param  packet         Packet.
 * @param  title          Title for the field.
 * @param  byte_start     Byte start position.
 * @param  bit_offset     Bit offset.
 * @param  bit_block_size Size of each value (bits)
 * @param  length         Number of values to extract.
 * @param  format         Format to print the value.
 * @param  f_inf          A function that, when given the array of values extracted, will return a string 
 *                        with additional information for those values. For example, it can be used
 *                        to output protocol names.		
 * @return                0 if OK, < 0 if error.
 */
int print_packet_field_i(const uint8_t* packet, const char* title, int byte_start, int bit_offset, int bit_block_size, int length, format_type format, informer f_inf);
#endif
