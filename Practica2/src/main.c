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

volatile sig_atomic_t ctrl_pressed = 0;

pcap_t *descr;
u_int64_t cont = 0;

void handleSignal(int nsignal)
{
    printf("Control-C pulsado\n");
    ctrl_pressed = 1;
}



int main(const int argc, const char **argv)
{
    char errbuf[PCAP_ERRBUF_SIZE];
    u_int8_t *paquete;
    struct pcap_pkthdr *cabecera;
    int retorno;
    int capture_retval,cont_filtered_packets=0;
    int retval = OK;
    args filter_values;
    double filter_percentage;
    const char* file;

    short parser_retval = arg_parser(argc, argv,&filter_values);

    if (parser_retval == ERROR){
        printf("Error en los argumentos introducidos\n");
        return ERROR;        
    }


    if (signal(SIGINT, handleSignal) == SIG_ERR)
    {
        printf("Error: Fallo al capturar la senal SIGINT.\n");
        exit(ERROR);
    }

    if(parser_retval == NO_FILE)
    {
        descr = pcap_open_live("eth0", 100, 0, 0, errbuf);
        file = "eth0";
    }
    else
    {
        descr = pcap_open_offline(argv[1], errbuf);
        file = argv[1];
    }

    if (descr == NULL)
    {
        printf("Error: pcap_open: File: %s, %s %s %d.\n", file, errbuf, __FILE__, __LINE__);
        exit(ERROR);
    }

    printf("Leyendo paquetes en %s...\n", file);

    while (ctrl_pressed == 0 && (capture_retval = pcap_next_ex(descr, &cabecera, (const u_char **) (&paquete))) == 1)
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
        filter_percentage = 100 * (double) cont_filtered_packets / cont;
        printf("No hay mas paquetes.\n");
        printf("Estadísticas:\n\tCapturados: %" PRIu64 "\n\tDescartados: %"PRIu64" (%.2lf %%)\n\tAceptados: %d (%.2lf %%)\n",
                cont,
                cont - cont_filtered_packets, 100 - filter_percentage,
                cont_filtered_packets, filter_percentage
                );
    }

    pcap_close(descr);

    return retval;
}
