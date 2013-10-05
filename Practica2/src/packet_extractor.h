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
#define FIELD_END -1
typedef enum {
	HEX, DEC
} format_type;

struct packet_val
{
	short size;
	union 
	{
		uint8_t uint8[MAX_VAL_LEN];
		uint16_t uint16[MAX_VAL_LEN];
		uint32_t uint32[MAX_VAL_LEN];
	} v;
};

int extract_bytes(const uint8_t* packet, int start, int num, uint8_t* dest);
int extract(const uint8_t* packet, int bit_start, int num, struct packet_val* value);
int printf_hex(const struct packet_val* value, int len);
int printf_dec(const struct packet_val* value, int len);
int print_packet_field(const uint8_t* packet, const char* title, int byte_start, int bit_offset, int bit_block_size, int length, format_type format);
#endif
