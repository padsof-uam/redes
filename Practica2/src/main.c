#include <stdio.h>
#include <stdlib.h>
#include <inttypes.h>
#include <pcap.h>
#include <string.h>
#include <netinet/in.h>
#include <signal.h>
#include <time.h>

#include "filter.h"

void handleSignal(int nsignal);

pcap_t *descr;
u_int64_t cont = 0;

void handleSignal(int nsignal)
{
    printf("Control-C pulsado (%" PRIu64 ")\n", cont);
    pcap_close(descr);
    exit(OK);
}



int main(const int argc, const char **argv)
{
    char errbuf[PCAP_ERRBUF_SIZE];
    u_int8_t *paquete;
    struct pcap_pkthdr *cabecera;
    u_int8_t retorno;
    int capture_retval,cont_filtered_packets=0;
    int retval = OK;
    args filter_values;

    short aux = arg_parser(argc, argv,&filter_values);

    if (aux == ERROR){
        printf("Error en los argumentos introducidos\n");
        return ERROR;        
    }


    if (signal(SIGINT, handleSignal) == SIG_ERR)
    {
        printf("Error: Fallo al capturar la senal SIGINT.\n");
        exit(ERROR);
    }


    descr = pcap_open_offline(argv[1], errbuf);
    if (descr == NULL)
    {
        printf("Error: pcap_open_offline(): File: %s, %s %s %d.\n", argv[1], errbuf, __FILE__, __LINE__);
        exit(ERROR);
    }

    while ((capture_retval = pcap_next_ex(descr, &cabecera, (const u_char **) (&paquete))) == 1)
    {
        cont++;

        if ((retorno = analizarPaquete(paquete, cabecera, &filter_values)) == ERROR)
        {
            printf("Error al analizar el paquete %" PRIu64 "; %s %d.\n", cont, __FILE__, __LINE__);
            exit(retorno);
        }
        cont_filtered_packets += retorno;
    }

    if (capture_retval == -1)
    {
        printf("Error: pcap_open_offline(): File: %s, %s %s %d.\n", argv[1], errbuf, __FILE__, __LINE__);
        pcap_perror(descr, "pcap error:");

        retval = ERROR;
    }
    else // PCAP_ERROR_BREAK es la otra salida posible, hemos llegado a final de archivo.
    {
        printf("No hay mas paquetes.\n Capturados %" PRIu64 " paquetes.\n\n", cont);
        printf("Paquetes después del filtro: %d\n", cont_filtered_packets);
    }

    pcap_close(descr);

    return retval;
}
