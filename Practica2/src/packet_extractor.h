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

int extract_bytes(uint8_t* packet, int start, int num, uint8_t* dest);
int extract(uint8_t* packet, int bit_start, int bit_block_size, int num, void* value);
void printf_hex(uint8_t* value, int len);
#endif
