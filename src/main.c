/***************************************************************************
Ejemplo pcap_next.pcap
gcc -o EjemploPcapNext EjemploPcapNext.c -lpcap
***************************************************************************/

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdio.h>
#include <stdlib.h>

#include <pcap.h>
#include <string.h>
#include <netinet/in.h>
#include <linux/udp.h>
#include <linux/tcp.h>
#include <signal.h>
#include <time.h>

#define OK 0
#define ERROR 1

#define HEAD_SIZE 10


// Demasiada variable global pululando.
static pcap_t *_iface_capturer = NULL;
static pcap_t *_dumpfile = NULL;
static pcap_dumper_t *_dumper = NULL;
static int _packet_count = 0;

void close_handlers()
{
    if (_iface_capturer) pcap_close(_iface_capturer);
    if (_dumper) pcap_dump_close(_dumper);
    if (_dumpfile) pcap_close(_dumpfile);
}

void handle(int nsignal)
{
    close_handlers();
    printf("Recibidos %d paquetes.\n", _packet_count);
    exit(0);
}

void print_packet(struct pcap_pkthdr *header, u_char *packet)
{
    int j;

    printf("Paquete capturado. Diez primeros bytes: 0x");

    for (j = 0; j < header->caplen && j < HEAD_SIZE; j++)
        printf("%02x", packet[j]);

    printf("\n");
}

int live_capture()
{
    int packet_count;
    char errbuf[PCAP_ERRBUF_SIZE];

    u_char *packet;
    struct pcap_pkthdr h;
    pcap_t *_iface_capturer;
    pcap_t *_dumpfile;
    pcap_dumper_t *_dumper;
    int result = OK;

    if (signal(SIGINT, handle) == SIG_ERR)
    {
        printf("Error: Fallo al capturar la senal SIGINT.\n");
        close_handlers();
        return ERROR;
    }

    if ((_iface_capturer = pcap_open_live("eth0", 10, 0, 0, errbuf)) == NULL)
    {
        printf("Error: pcap_open_live(): %s %s %d.\n", errbuf, __FILE__, __LINE__);
        close_handlers();
        return ERROR;
    }

    _dumpfile = pcap_open_dead(DLT_EN10MB, 1514);

    if (!_dumpfile)
    {
        printf("Error: pcap_open_dead(): %s %s %d.\n", errbuf, __FILE__, __LINE__);
        close_handlers();
        return ERROR;
    }

    _dumper = pcap_dump_open(_dumpfile, "out.pcap");

    if (!_dumper)
    {
        printf("Error: pcap_open_live(): %s %s %d.\n", errbuf, __FILE__, __LINE__);
        close_handlers();
        return ERROR;
    }

    packet_count = 0;

    while (1) // Seguimos recibiendo hasta que recibimos una señal.
    {
        if ((packet = (u_int8_t *) pcap_next(_iface_capturer, &h)) == NULL)
        {
            printf("Error al capturar el paquete %s %d.\n", __FILE__, __LINE__);
            close_handlers();
            return ERROR;
        }

        print_packet(&h, packet);
        pcap_dump((u_char *) _dumper, &h, packet);

        _packet_count++;
    }

    // No se llega nunca a esto, pero por si acaso.
    close_handlers();
    return result;
}

int open_file(const char *path)
{
    char errbuf[PCAP_ERRBUF_SIZE];
    int packet_count = 0;
    pcap_t *file;

    struct pcap_pkthdr h;

    file = pcap_open_offline(path, errbuf);

    if (!file)
    {
        printf("Error: pcap_open_offline(): %s %s %d.\n", errbuf, __FILE__, __LINE__);
        return ERROR;
    }
    u_char *packet;
    while ((packet = (u_int8_t *) pcap_next(file, &h)) != NULL)
    {
        print_packet(&h, packet);
        packet_count++;
    }

    printf("%d paquetes en el archivo %s.\n", packet_count, path);

    return OK;
}

int main(int argc, char **argv)
{
    int result;

    if (argc == 1)
        result = live_capture();
    else
        result = open_file(argv[1]);

    return result;
}

