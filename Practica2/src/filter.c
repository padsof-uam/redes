#include "filter.h"

short arg_parser(const int argc, const char **argv, filter_params *args)
{
    short retval = OK;
    int i = 2;

    args->ip_dst = -1;
    args->ip_src = -1;
    args->port_dst = -1;
    args->port_src = -1;

    if(argc == 1 || (argc >= 2 && argv[1][0] == '-'))
    {
        i = 1;
        retval = NO_FILE;
    }

    for (; i < argc && retval != ERROR; i += 2)
    {
        if (args->ip_src == -1 && !strcmp(argv[i], "-ipo"))
            args->ip_src = ip_fromstr(argv[i + 1]);
        else if (args->ip_dst == -1 && !strcmp(argv[i], "-ipd"))
            args->ip_dst = ip_fromstr(argv[i + 1]);
        else if (args->port_src == -1 && !strcmp(argv[i], "-po"))
            args->port_src = atoi(argv[i + 1]);
        else if (args->port_dst == -1 && !strcmp(argv[i], "-pd"))
            args->port_dst = atoi(argv[i + 1]);
        else
            retval = ERROR; // Unknown or repeated parameter.
    }

    return retval;
}

/**
 * Macro to reject a packet based on a parameter
 * @param  what Valor a parameters.
 */
#define CHECKFOR(what) if(what != -1 && p_##what != what) return 1;

short filter(u_int8_t *packet, uint32_t eth_type, filter_params *args)
{
    uint32_t p_eth_type, p_protocol, p_ip_dst, p_ip_src, p_port_dst, p_port_src;
    uint32_t ip_dst, ip_src, port_dst, port_src;
    uint32_t ip_header_size;

    ip_dst = args->ip_dst;
    ip_src = args->ip_src;
    port_dst = args->port_dst;
    port_src = args->port_src;

    extract(packet, ETH_ALEN * 2, 1, 16, &p_eth_type);

    CHECKFOR(eth_type);

    packet += ETH_ALEN * 2 + ETH_TLEN; // ETH header end.

    extract_offset(packet, 0, 4, 1, 4, &ip_header_size);

    extract(packet, 9, 1, 8, &p_protocol);
    extract(packet, 12, 1, 32, &p_ip_src);
    extract(packet, 16, 1, 32, &p_ip_dst);

    if (p_protocol != UDP && p_protocol != TCP)
        return 1;

    CHECKFOR(ip_src);
    CHECKFOR(ip_dst);

    packet += ip_header_size * 4; // IP header end.

    extract(packet, 0, 1, 16, &p_port_src);
    extract(packet, 2, 1, 16, &p_port_dst);

    CHECKFOR(port_src);
    CHECKFOR(port_dst);

    return 0;
}

uint32_t ip_fromstr(const char *ipstr)
{
    char *dup = strdup(ipstr);
    char *tofree = dup;
    char *token;
    int i;
    uint32_t val = 0;

    for (i = 3; i >= 0; i--)
    {
        token = strsep(&dup, ".");

        if (token == NULL)
            return -1;

        val += atoi(token) << (8 * i);
    }

    free(tofree);
    return val;
}

/**
 * Returns a string describing the protocol of the packet
 */
static const char *proto_informer(const uint32_t *values)
{
    switch (values[0])
    {
        case TCP:
            return "TCP";
        case UDP:
            return "UDP";
        default:
            return "Unknown";
    }
}

int analizarPaquete(u_int8_t *paquete, struct pcap_pkthdr *cabecera, filter_params *args, int cont)
{
    uint32_t ip_header_size;
    uint32_t protocol;
    int filtered;

    filtered = filter(paquete, 0x0800, args);

    if (filtered != 0)
        return 0;

    printf("Paquete n. %d \n", cont);

    print_packet_field(paquete, "MAC destino", 0, 0, 8, ETH_ALEN, HEX);
    print_packet_field(paquete, "MAC origen", ETH_ALEN, 0, 8, ETH_ALEN, HEX);
    print_packet_field(paquete, "Tipo ETH", ETH_ALEN * 2, 0, 16, 1, HEX);

    // ETH end.
    paquete += ETH_ALEN * 2 + ETH_TLEN;
    
    // IP Start.
    print_packet_field(paquete, "Versión IP", 0, 0, 4, 1, DEC);
    print_packet_field(paquete, "Long. header", 0, 4, 4, 1, DEC);
    print_packet_field(paquete, "Longitud", 2, 0, 16, 1, DEC);
    print_packet_field(paquete, "Posición", 6, 3, 13, 1, DEC);
    print_packet_field(paquete, "TTL\t", 8, 0, 8, 1, DEC);
    print_packet_field_i(paquete, "Protocolo", 9, 0, 8, 1, DEC, proto_informer);
    print_packet_field(paquete, "IP origen", 12, 0, 8, 4, DEC);
    print_packet_field(paquete, "IP destino", 16, 0, 8, 4, DEC);

    extract(paquete, 9, 1, 8, &protocol);
    extract_offset(paquete, 0, 4, 1, 4, &ip_header_size);

    // IP end.
    paquete += ip_header_size * 4;

    // TCP/UDP start.
    print_packet_field(paquete, "Puerto origen", 0, 0, 16, 1, DEC);
    print_packet_field(paquete, "Puerto destino", 2, 0, 16, 1, DEC);

    if (protocol == UDP)
        print_packet_field(paquete, "Long. UDP", 4, 0, 16, 1, DEC);

    printf("\n");

    return 1;
}


