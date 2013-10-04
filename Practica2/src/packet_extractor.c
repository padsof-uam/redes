#include "packet_extractor.h"

int extract(uint8_t* packet, int bit_start, int bit_block_size, int num, void* value)
{
	int bytes_per_value;
	uint8_t uint8val;
	uint8_t* destiny = value;
	int size_shift, position_shift;
	int i, byte_start;

	if(bit_block_size < 8)
		size_shift = 8 - bit_block_size;
	else
		size_shift = 0;

	bytes_per_value = (bit_block_size / 8) || 1;

	for(i = 0; i < num; i++)
	{
		byte_start = bit_start / 8;
		position_shift = bit_start - byte_start * 8;

		if(bit_block_size < 8)
		{
			memcpy(&uint8val, packet + byte_start, 1);
			uint8val = uint8val << position_shift;
			uint8val = uint8val >> size_shift;
			memcpy(destiny + i, &uint8val, 1);
		}
		else
		{
			memcpy(destiny + i * bytes_per_value, packet + byte_start, bytes_per_value);
		}

		bit_start += bit_block_size;
	}

	return 0;
}

void printf_hex(uint8_t* value, int len)
{
	int i;

	printf("%02X", value[0]);
	for(i = 1; i < len; i++)
		printf(":%02X", value[i]);
}


int extract_bytes(uint8_t* packet, int start, int num, uint8_t* dest)
{
	return extract(packet, start * 8, 8, num, dest);
}
