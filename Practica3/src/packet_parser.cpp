#include "packet_parser.h"

/**
 * Extracts a value from a packet.
 * @param  packet    Packet.
 * @param  bit_start Starting bit.
 * @param  value     Struct where the value will be saved.
 * @return           0 if OK, -1 otherwise. 
 */
static int _extract(const uint8_t *packet, int bit_start, struct packet_val *value)
{
    uint8_t uint8val;
    int bit_block_size = value->size;
    int size_shift, position_shift;
    int i, byte_start;

    size_shift = bit_block_size < 8 ? 8 - bit_block_size : 0;

    for (i = 0; i < value->num_values; i++)
    {
        byte_start = bit_start / 8;
        position_shift = bit_start - byte_start * 8;

        if (bit_block_size <= 8)
        {
            memcpy(&uint8val, packet + byte_start, 1);
            uint8val = uint8val << position_shift;
            uint8val = uint8val >> size_shift;
            memcpy(value->v.uint8 + i, &uint8val, 1);
        }
        else if (bit_block_size == 16)
        {
            memcpy(value->v.uint16 + i, packet + byte_start, 2);
            value->v.uint16[i] = ntohs(value->v.uint16[i]);
        }
        else if (bit_block_size == 32)
        {
            memcpy(value->v.uint32 + i, packet + byte_start, 4);
            value->v.uint32[i] = ntohl(value->v.uint32[i]);
        }
        else
        {
            return ERR_UNSUPPORTED_SIZE;
        }

        bit_start += bit_block_size;
    }

    return 0;
}

int printf_val(const u_int32_t* values, int length, format_type type, int byte_size)
{
    const char *format;
    const char* separator;
    int i;
    char format_str[256];

    if (type == DEC)
    {
    	separator = ".";

    	format = PRIu32;
    }
    else if (type == HEX)
    {
    	separator = ":";

        if (byte_size == 1)
            format = "02X";
        else if (byte_size == 2)
            format = "04X";
        else if (byte_size == 4)
            format = "08X";
        else
            return ERR_UNSUPPORTED_SIZE;
    }
    else
    {
        return ERR_UNSUPPORTED_FORMAT;
    }

    sprintf(format_str, "%%%s", format);

    if(type == HEX && length == 1)
    	printf("0x");

    printf(format_str, values[0]);

    for (i = 1; i < length; i++)
    {
        printf("%s", separator);
        printf(format_str, values[i]);
    }

    return 0;
}

static int packet_val_toint(const struct packet_val* value, uint32_t* array)
{
	int i, datasize;	

	datasize = TOBYTESIZE(value->size);

	memset(array, 0, sizeof(uint32_t) * (value->num_values));

	for(i = 0; i < value->num_values; i++)
		memcpy(array + i, value->v.uint8 + datasize * i, datasize); // Podemos usar value->v.uint8 porque v es union y todos los punteros están en la misma posición.

	return 0;
}

int print_packet_field(const uint8_t* packet, const char* title, int byte_start, int bit_offset, int bit_block_size, int length, format_type format)
{
	return print_packet_field_i(packet, title, byte_start, bit_offset, bit_block_size, length, format, NULL);
}

int print_packet_field_i(const uint8_t* packet, const char* title, int byte_start, int bit_offset, int bit_block_size, int length, format_type format, informer f_inf)
{
    uint32_t* values = (uint32_t*) calloc(length, sizeof(uint32_t));

    int retval;

    retval = extract_offset(packet, byte_start, bit_offset, length, bit_block_size, values);

    if(retval != 0)
    	return retval;

    printf("%s:\t", title);

    retval = printf_val(values, length, format, TOBYTESIZE(bit_block_size));

    if(retval != 0)
    {
        free(values);
    	return retval;
    }

    if(f_inf != NULL)
    	printf(" (%s)", f_inf(values));

    printf("\n");

    free(values);

    return 0;
}

int extract(const uint8_t* packet, int byte_start, int num, int bit_block_size, u_int32_t* array)
{
	return extract_offset(packet, byte_start, 0, num, bit_block_size, array);
}

int extract_offset(const uint8_t* packet, int byte_start, int bit_offset, int length, int bit_block_size, u_int32_t* array)
{
	struct packet_val value;
	value.num_values = length;
	value.size = bit_block_size;

	_extract(packet, byte_start*8 + bit_offset, &value);

	return packet_val_toint(&value, array);
}

