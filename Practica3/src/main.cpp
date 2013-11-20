#ifndef __STDC_FORMAT_MACROS
#define __STDC_FORMAT_MACROS 1
#endif
 

#include <cstdio>
#include <inttypes.h>
#include <pcap.h>
#include <string.h>
#include <netinet/in.h>
#include <signal.h>
#include <time.h>
#include <errno.h>

#include "filter.h"
#include "stats.h"

void handleSignal(int nsignal);

volatile sig_atomic_t ctrl_pressed = 0;

void handleSignal(int nsignal)
{
    printf("Control-C pulsado\n");
    ctrl_pressed = 1;
}

/**
 * Prints capture session stats.
 */
void print_stats(int total_packets, int accepted, long start, long end);

/**
 * Return miliseconds since epoch.
 */
long get_ms_time();

int main(const int argc, const char **argv)
{
    pcap_t* descr;
    char errbuf[PCAP_ERRBUF_SIZE];
    u_int8_t *paquete;
    struct pcap_pkthdr *cabecera;
    int retorno;
    int capture_retval;
    int retval = OK;
    filter_params fparams;
    const char *file;;
    int cont = 0;

    short parser_retval = arg_parser(argc, argv, &fparams);

    if (parser_retval == ERROR)
    {
        fprintf(stderr, "Error en los argumentos introducidos.\n");
        return ERROR;
    }

    if (signal(SIGINT, handleSignal) == SIG_ERR)
    {
        fprintf(stderr, "Error: Fallo al capturar la senal SIGINT.\n");
        exit(ERROR);
    }

    Stats stats(&fparams);

    file = argv[1];
    
    if (parser_retval == NO_FILE)
        descr = pcap_open_live(file, 100, 0, 0, errbuf);
    else
        descr = pcap_open_offline(file, errbuf);

    if (descr == NULL)
    {
        fprintf(stderr, "Error: pcap_open: File: %s, %s %s %d.\n", file, errbuf, __FILE__, __LINE__);
        exit(ERROR);
    }

    printf("Leyendo paquetes en %s...\n", file);

    while (ctrl_pressed == 0 && (capture_retval = pcap_next_ex(descr, &cabecera, (const u_char **) (&paquete))) == 1)
    {
        if(ctrl_pressed)
            break;

        cont++;

        if ((retorno = analizarPaquete(paquete, cabecera, &fparams,cont)) == ERROR)
        {
            fprintf(stderr, "Error al analizar el paquete %d; %s %d.\n", cont, __FILE__, __LINE__);
            exit(retorno);
        }

        stats.parse_packet(paquete, cabecera, retorno);
    }

    if (capture_retval == -1)
    {
        fprintf(stderr, "Error: pcap_open_offline(): File: %s, %s %s %d.\n", argv[1], errbuf, __FILE__, __LINE__);
        pcap_perror(descr, (char*) "pcap error:");

        retval = ERROR;
    }
    else // PCAP_ERROR_BREAK es la otra salida posible, hemos llegado a final de archivo.
    {
        printf("Fin de la captura.\n");
        stats.print_stats();
    }

    pcap_close(descr);

    return retval;
}
