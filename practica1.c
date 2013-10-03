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

volatile sig_atomic_t ctr_pressed = 0;

void handle(int nsignal)
{
    ctr_pressed = 1;
}

void print_packet(struct pcap_pkthdr *header, u_char *packet)
{
    int j;

    printf("Paquete capturado. Imprimiendo diez primeros bytes: 0x");

    for (j = 0; j < header->caplen && j < HEAD_SIZE; j++)
        printf("%x", packet[j]);
    printf("\n");
}

int live_capture()
{
    int packet_count;
    char errbuf[PCAP_ERRBUF_SIZE];
    
u_char *packet;
    struct pcap_pkthdr h;
    pcap_t *eth0;
    pcap_t *dump_descr;
    pcap_dumper_t *dumper;
    int result = OK;

    if (signal(SIGINT, handle) == SIG_ERR)
    {
        printf("Error: Fallo al capturar la senal SIGINT.\n");
        result = ERROR;
        goto cleanup;
    }

    if ((eth0 = pcap_open_live("eth0", 10, 0, 0, errbuf)) == NULL)
    {
        printf("Error: pcap_open_live(): %s %s %d.\n", errbuf, __FILE__, __LINE__);
        result = ERROR;
        goto cleanup;
    }

    //new
    dump_descr = pcap_open_dead(DLT_EN10MB, 1514);

    if (!dump_descr)
    {
        printf("Error: pcap_open_dead(): %s %s %d.\n", errbuf, __FILE__, __LINE__);
        result = ERROR;
        goto cleanup;
    }

    dumper = pcap_dump_open(dump_descr, "out.pcap");

    if (!dumper)
    {
        printf("Error: pcap_open_live(): %s %s %d.\n", errbuf, __FILE__, __LINE__);
        result = ERROR;
        goto cleanup;
    }

    //unnew
    packet_count = 0;

    while (!ctr_pressed)
    {
        if ((packet = (u_int8_t *) pcap_next(eth0, &h)) == NULL)
        {
            printf("Error al capturar el paquete %s %d.\n", __FILE__, __LINE__);
            result = ERROR;
            goto cleanup;
        }

        print_packet(&h, packet);
        pcap_dump(dumper, &h, packet);

        packet_count++;
    }
    printf("Recibidos %d paquetes.\n", packet_count);

cleanup:
    if (eth0) pcap_close(eth0);
    if (dumper) pcap_dump_close(dumper);
    if (dump_descr) pcap_close(dump_descr);

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

