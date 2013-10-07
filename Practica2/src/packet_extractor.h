#ifndef PACKET_EXTRACTOR_H
#define PACKET_EXTRACTOR_H

#include <stdio.h>
#include <stdlib.h>
#include <inttypes.h>
#include <pcap.h>
#include <string.h>
#include <netinet/in.h>
#include <signal.h>
#include <time.h>
#include <stdarg.h>

#define MAX_VAL_LEN 20
#define ERR_UNSUPPORTED_SIZE -10
#define ERR_UNSUPPORTED_FORMAT -11
#define FIELD_END -1

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

int extract(const uint8_t* packet, int byte_start, int num, int bit_block_size, u_int32_t* array);
int extract_offset(const uint8_t* packet, int byte_start, int bit_offset, int num, int bit_block_size, uint32_t* array);
int printf_val(const u_int32_t* values, int length, format_type type, int byte_size);
int print_packet_field(const uint8_t* packet, const char* title, int byte_start, int bit_offset, int bit_block_size, int length, format_type format);
int print_packet_field_i(const uint8_t* packet, const char* title, int byte_start, int bit_offset, int bit_block_size, int length, format_type format, informer f_inf);
#endif
