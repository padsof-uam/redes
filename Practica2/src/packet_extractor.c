#include "packet_extractor.h"
#include <stdarg.h>

int extract(const uint8_t *packet, int bit_start, int num, struct packet_val *value)
{
    int bytes_per_value;
    uint8_t uint8val;
    int bit_block_size = value->size;
    int size_shift, position_shift;
    int i, byte_start;

    if (bit_block_size < 8)
    {
        size_shift = 8 - bit_block_size;
        bytes_per_value = 1;
    }
    else
    {
        size_shift = 0;
        bytes_per_value = bit_block_size / 8;
    }

    for (i = 0; i < num; i++)
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

static void _printf8(const uint8_t *array, const char *format, int length, const char *separator)
{
    int i;
    printf(format, array[0]);

    for (i = 1; i < length; i++)
    {
        printf("%s", separator);
        printf(format, array[i]);
    }
}

static void _printf16(const uint16_t *array, const char *format, int length, const char *separator)
{
    int i;
    printf(format, array[0]);

    for (i = 1; i < length; i++)
    {
        printf("%s", separator);
        printf(format, array[i]);
    }
}

static void _printf32(const uint32_t *array, const char *format, int length, const char *separator)
{
    int i;
    printf(format, array[0]);

    for (i = 1; i < length; i++)
    {
        printf("%s", separator);
        printf(format, array[i]);
    }
}

static void _printf(const struct packet_val *value, const char *format, int length, const char *separator)
{
    if (value->size <= 8)
        _printf8(value->v.uint8, format, length, separator);
    else if (value->size == 16)
        _printf16(value->v.uint16, format, length, separator);
    if (value->size == 32)
        _printf32(value->v.uint32, format, length, separator);
}

int printf_val(const struct packet_val *value, int len, format_type type)
{
    const char *format;
    const char* separator;
    int size = value->size / 8;
    char format_str[256];

    if (size == 0)
        size = 1;

    if (type == DEC)
    {
    	separator = ".";

        if (value->size <= 8)
            format = PRIu8;
        else if (value->size == 16)
            format = PRIu16;
        else if (value->size == 32)
            format = PRIu32;
        else
            return ERR_UNSUPPORTED_SIZE;
    }
    else if (type == HEX)
    {
    	separator = ":";

        if (value->size <= 8)
            format = "02X";
        else if (value->size == 16)
            format = "04X";
        else if (value->size == 32)
            format = PRIX32;
        else
            return ERR_UNSUPPORTED_SIZE;
    }
    else
    {
        return ERR_UNSUPPORTED_FORMAT;
    }

    sprintf(format_str, "%%%s", format);

    if(type == HEX && len == 1)
    	printf("0x");

    _printf(value, format_str, len, separator);

    return 0;
}

int print_packet_field(const uint8_t *packet, const char *title, int byte_start, int bit_offset, int bit_block_size, int length, format_type format)
{
    struct packet_val value;
    int retval;
    value.size = bit_block_size;

    retval = extract(packet, byte_start * 8 + bit_offset, length, &value);

    if (retval != 0)
        return retval;

    printf("%s:\t", title);

    printf_val(&value, length, format);

    printf("\n");

    return 0;
}
