/***************************************************************************
Fecha: 18 Nov 2013
Redes de comunicaciones I
Inicio, funciones auxiliares y modulos de transmision de la practica4
***************************************************************************/

#include <stdio.h>
#include <stdlib.h>
#include <errno.h> 
#include "interface.h"
#include "practica4.h"

/***************************Variables globales utiles*************************************************/
pcap_t* descr, *descr2; //Descriptores de la interface de red
pcap_dumper_t * pdumper;//  y salida a pcap
uint64_t cont=0;	//Contador numero de mensajes enviados
char* interface;	//Interface donde transmitir por ejemplo "eth0"
uint16_t ID=1;		//Identificador IP


static pf_notificacion protocolos_registrados[MAX_PROTOCOL];


void handleSignal(int nsignal){
	printf("Control C pulsado (\t%" PRIu64")\n", cont);
	pcap_close(descr);
	exit(OK);
}

int main(int argc, char **argv){	
	char errbuf[PCAP_ERRBUF_SIZE];
	char fichero_pcap_destino[CADENAS];
	uint8_t IP_destino_red[IP_ALEN];
	uint16_t MTU;
	uint16_t datalink;
	uint16_t puerto_destino;
	char data[IP_DATAGRAM_MAX];
	uint16_t pila_protocolos[CADENAS];
	struct pcap_pkthdr * header;


		//Dos opciones: leer de stdin o de fichero, adicionalmente para pruebas si no se introduce argumento se considera que el mensaje es "Payload "
	if(argc!=5 && argc!=4 ){
		printf("Ejecucion: %s interface IP Puerto </ruta/fichero_a_transmitir o stdin> \n",argv[0]);
		return ERROR;
	}
	if(argc==5 ){
		if(strcmp(argv[4],"stdin")==0){
			if (fgets(data, sizeof(data), stdin)==NULL){
			      	printf("Error leyendo desde stdin: %s %s %d.\n",errbuf,__FILE__,__LINE__);
				return ERROR;
    			}
			sprintf(fichero_pcap_destino,"%s%s","stdin",".pcap");
		}else{
			sprintf(fichero_pcap_destino,"%s%s",argv[4],".pcap");
			if(read_from_file(argv[4], IP_DATAGRAM_MAX, data) == ERROR)
			{
				fprintf(stderr, "practica4: error leyendo fichero %s: %d (%s)\n", argv[4], errno, strerror(errno));
			}
		}
	}	
	else{
		sprintf(data,"%s","Payload ");
		sprintf(fichero_pcap_destino,"%s%s","debugging",".pcap");
	}

	if(signal(SIGINT,handleSignal)==SIG_ERR){
		printf("Error: Fallo al capturar la senal SIGINT.\n");
		return ERROR;
	}
		//Inicializamos las tablas de protocolos
	if(inicializarPilaEnviar()==ERROR){
			      	printf("Error leyendo desde stdin: %s %s %d.\n",errbuf,__FILE__,__LINE__);
				return ERROR;
		}
		//Por comodidad definimos interface como una variable global
	interface=argv[1];
		//Leemos la IP a donde transmitir y la almacenamos en orden de red
	if(sscanf(argv[2],"%" SCNu8 ".%" SCNu8 ".%" SCNu8 ".%" SCNu8 "",&(IP_destino_red[0]),&(IP_destino_red[1]),&(IP_destino_red[2]),&(IP_destino_red[3]))!=IP_ALEN){
		printf("Error: Fallo en la lectura IP destino %s\n",argv[2]);
		return ERROR;
	}
		//Leemos el puerto a donde transmitir y la almacenamos en orden de hardware
	puerto_destino=atoi(argv[3]);
		//Leemos el tamano maximo de transmision del nivel de enlace
	if(obtenerMTUInterface(interface, &MTU)==ERROR)
		return ERROR;
		//Descriptor de la interface de red donde inyectar trafico
	if ((descr = pcap_open_live(interface,MTU+ETH_HLEN,0, 0, errbuf)) == NULL){
		printf("Error: pcap_open_live(): %s %s %d.\n",errbuf,__FILE__,__LINE__);
		return ERROR;
	}
	datalink=(uint16_t)pcap_datalink(descr); //DLT_EN10MB==Ethernet
		//Descriptor del fichero de salida pcap para debugging
	descr2=pcap_open_dead(datalink,MTU+ETH_HLEN);
	pdumper=pcap_dump_open(descr2,fichero_pcap_destino);

		//Formamos y enviamos el trafico, debe enviarse un unico segmento por llamada a enviar() aunque luego se traduzca en mas de un datagrama
		//Primero un paquete UDP
		//Definimos la pila de protocolos que queremos seguir
	pila_protocolos[0]=UDP_PROTO;
	pila_protocolos[1]=IP_PROTO; 
	pila_protocolos[2]=ETH_PROTO;
		//Rellenamos los parametros necesario para enviar el paquete a su destinatario y proceso
	Parametros parametros_udp;
	memcpy(parametros_udp.IP_destino,IP_destino_red,IP_ALEN);
	parametros_udp.puerto_destino = puerto_destino;
		//Enviamos
	if(enviar((uint8_t*)data,pila_protocolos,strlen(data),&parametros_udp)==ERROR ){
		printf("Error: enviar(): %s %s %d.\n",errbuf,__FILE__,__LINE__);
		return ERROR;
	}
	else	cont++;

	printf("Enviado mensaje \t%" PRIu64", almacenado en %s\n\n\n", cont,fichero_pcap_destino);


		//Luego un paquete ICMP en concreto un ping

	printf("Vamos con el ping\n");
	pila_protocolos[0]=ICMP_PROTO;
	pila_protocolos[1]=IP_PROTO;
	pila_protocolos[2]=ETH_PROTO;

	Parametros parametros_icmp;
	parametros_icmp.tipo=PING_TIPO;
	parametros_icmp.codigo=PING_CODE;
	memcpy(parametros_icmp.IP_destino,IP_destino_red,IP_ALEN);
	parametros_icmp.puerto_destino=0;

 	if(enviar((uint8_t*)"Probando a hacer un ping",pila_protocolos,strlen("Probando a hacer un ping"),&parametros_icmp)==ERROR ){
		printf("Error: enviar(): %s %s %d.\n",errbuf,__FILE__,__LINE__);
		return ERROR;
	}
	else	cont++;
	printf("Enviado mensaje \t%" PRIu64", ICMP almacenado en %s\n\n", cont,fichero_pcap_destino);

		//Cerramos descriptores
	pcap_close(descr);
	pcap_dump_close(pdumper);
	pcap_close(descr2);
	return OK;
}


/****************************************************************************************
* Nombre: enviar 									*
* Descripcion: Esta funcion envia un mensaje						*
* Argumentos: 										*
*  -mensaje: mensaje a enviar								*
*  -pila_protocolos: conjunto de protocolos a seguir					*
*  -longitud: bytes que componen mensaje						*
*  -parametros: Parametros necesario para el envio (struct parametros)			*
* Retorno: OK/ERROR									*
****************************************************************************************/

uint8_t enviar(uint8_t* mensaje, uint16_t* pila_protocolos,uint64_t longitud,void *parametros){
	uint16_t protocolo=pila_protocolos[0];
	printf("Enviar(%u) %s %d.\n",protocolo,__FILE__,__LINE__);
	if(protocolos_registrados[protocolo]==NULL){
		printf("Protocolo %" SCNu16 " desconocido\n",protocolo);
		return ERROR;
	}
	else {
		return protocolos_registrados[protocolo](mensaje,pila_protocolos,longitud,parametros);
	}
	return ERROR;
}


/***************************Pila de protocolos a implementar************************************/

/****************************************************************************************
* Nombre: moduloUDP 									*
* Descripcion: Esta funcion implementa el modulo de envio UDP				*
* Argumentos: 										*
*  -mensaje: mensaje a enviar								*
*  -pila_protocolos: conjunto de protocolos a seguir					*
*  -longitud: bytes que componen mensaje						*
*  -parametros: Parametros necesario para el envio este protocolo			*
* Retorno: OK/ERROR									*
****************************************************************************************/

uint8_t moduloUDP(uint8_t* mensaje, uint16_t* pila_protocolos,uint64_t longitud,void *parametros){
	uint8_t segmento[UDP_SEG_MAX]={0};
	uint16_t puerto_origen,suma_control=0;
	uint16_t aux16;
	uint16_t puerto_destino;
	uint32_t pos=0;
	uint16_t protocolo_inferior=pila_protocolos[1];
	printf("moduloUDP(%u) %s %d.\n",protocolo_inferior,__FILE__,__LINE__);
	Parametros UDP_data=*((Parametros*)parametros);

	if(longitud>pow(2,16)-UDP_HLEN){
		printf("Error: tamano demasiado grande para UDP (%f).\n",pow(2,16));
		return ERROR;
	}

//[...]

	obtenerPuertoOrigen(&puerto_origen);
	aux16=htons(puerto_origen);
	memcpy(segmento+pos,&aux16,sizeof(uint16_t));
	pos+=sizeof(uint16_t);

	puerto_destino=UDP_data.puerto_destino;
	aux16=htons(puerto_destino);
	memcpy(segmento+pos, &aux16, sizeof(uint16_t));
	pos+=sizeof(uint16_t);

	aux16=htons(longitud+UDP_HLEN);
	memcpy(segmento+pos, &aux16, sizeof(uint16_t));
	pos+=sizeof(uint16_t);

	aux16=0;
	memcpy(segmento+pos, &aux16, sizeof(uint16_t));
	pos+=sizeof(uint16_t);


	memcpy(segmento+pos, mensaje, longitud*sizeof(uint8_t));
			
	//Llamamos al protocolo definido de nivel inferior a traves de los punteros registrados en la tabla de protocolos registrados
	return protocolos_registrados[protocolo_inferior](segmento,pila_protocolos,longitud+pos,parametros);
}


/****************************************************************************************
* Nombre: moduloIP 									*
* Descripcion: Esta funcion implementa el modulo de envio IP				*
* Argumentos: 										*
*  -segmento: segmento a enviar								*
*  -pila_protocolos: conjunto de protocolos a seguir					*
*  -longitud: bytes que componen el segmento						*
*  -parametros: Parametros necesario para el envio este protocolo			*
* Retorno: OK/ERROR									*
****************************************************************************************/

uint8_t moduloIP(uint8_t* segmento, uint16_t* pila_protocolos,uint64_t longitud,void *parametros){
	uint8_t aux8;
	uint16_t aux16;
	uint32_t aux32;
	uint32_t pos_control=0;
	uint8_t pos=0,fragmentation=0;
	uint8_t datagrama[IP_DATAGRAM_MAX]={0};
	uint8_t IP_origen[IP_ALEN];
	uint8_t GateWay[IP_ALEN];
	uint8_t ETH_dest[ETH_ALEN];
	uint8_t * checksum = (uint8_t* ) calloc (2,sizeof(uint8_t));
	int num_packets=1,j,i;
	uint16_t protocolo_superior=pila_protocolos[0];
	uint16_t protocolo_inferior=pila_protocolos[2];
	uint16_t MTU,length_fragment,offset=0;

	uint8_t mascara[IP_ALEN],IP_rango_origen[IP_ALEN],IP_rango_destino[IP_ALEN];

	pila_protocolos++;

	printf("moduloIP(%u) %s %d.\n",protocolo_inferior,__FILE__,__LINE__);

	Parametros IP_data=*((Parametros*)parametros);
	uint8_t* IP_destino=IP_data.IP_destino;
	

	obtenerMTUInterface(interface, &MTU);

	if(longitud>MTU){
		fragmentation=1;
		num_packets = longitud/MTU;
	}

	obtenerMascaraInterface(interface, mascara);

	obtenerIPInterface(interface, IP_origen);

	aplicarMascara(IP_destino, mascara, IP_ALEN, IP_rango_destino);
	aplicarMascara(IP_origen, mascara, IP_ALEN, IP_rango_origen);

	for(i=0;i<IP_ALEN;++i)
		if(IP_rango_origen[i]!=IP_rango_destino[i])
			break;

	if (i!=4)
	{
		obtenerGateway(interface, GateWay);
		ARPrequest(interface, GateWay, ETH_dest);
		memcpy(IP_data.ETH_destino,ETH_dest,6*sizeof(uint8_t));
		printf("No pertenece a la subred\n");
	}
	else{
		ARPrequest(interface, IP_destino, ETH_dest);
		memcpy(IP_data.ETH_destino,ETH_dest,6*sizeof(uint8_t));
		printf("Pertenece a la subred\n");
	}

	for (j = 0; j < num_packets; ++j)
	{
		bzero(datagrama, IP_DATAGRAM_MAX);
		pos=sizeof(uint8_t);
		
		aux8=0;
		memcpy(datagrama+pos, &aux8, sizeof(uint8_t));
		pos+=sizeof(uint8_t);
		
		pos+=sizeof(uint16_t);

		//Identificación
		aux16=htons(666);
		memcpy(datagrama+pos, &aux16, sizeof(uint16_t));
		pos+=sizeof(uint16_t);


		aux16=offset;

		//flags
		if (j!=num_packets-1)
			aux16 = htons(aux16 | 0x2000);
		else
			aux16 = htons(aux16 & 0x1FFF);
		memcpy(datagrama+pos, &aux16, sizeof(uint16_t));
		pos+=sizeof(uint16_t);

		//Tiempo de vida
		aux8=128;
		memcpy(datagrama+pos, &aux8, sizeof(uint8_t));
		pos+=sizeof(uint8_t);

		if (IP_data.puerto_destino == 0)
			aux8=ICMP_PROTO;
		else 
			aux8=UDP_PROTO;

		memcpy(datagrama+pos, &aux8, sizeof(uint8_t));
		pos+=sizeof(uint8_t);

		//Checksum
		uint8_t pos_checkSum=pos;
		aux16=0;
		memcpy(datagrama+pos, &aux16, sizeof(uint16_t));
		pos+=sizeof(uint16_t);

		obtenerIPInterface(interface, IP_origen);
		for (i = 0; i < 4; ++i)
		{
			memcpy(datagrama+pos+i, &IP_origen[i], sizeof(uint8_t));
			memcpy(datagrama+pos+i+4*sizeof(uint8_t), &IP_destino[i], sizeof(uint8_t));
		}
		pos+=8*sizeof(uint8_t);

		//Opciones y relleno
		aux32=0;
		memcpy(datagrama+pos, &aux32, sizeof(uint32_t));
		pos+=sizeof(uint32_t);
		

		//Versión 4 y tamaño de la cabecera.
		aux8=64+pos/4;
		memcpy(datagrama, &aux8, sizeof(uint8_t));

		//habría que tener en cuenta la longitud dle paquete para la última fragmentación
		
		length_fragment = (MTU-pos) - (MTU-pos)%8;

		aux16=htons(length_fragment+pos);
		memcpy(datagrama+2*sizeof(uint8_t), &aux16, sizeof(uint16_t));

		calcularChecksum(length_fragment+pos, datagrama, checksum);

		memcpy(datagrama+pos_checkSum, checksum, 2*sizeof(uint8_t));

		//Copiamos el segmento que viene de UDP, con los datos.
		memcpy(datagrama+pos, segmento, sizeof(uint8_t)*(j+1)*(length_fragment));
		segmento+=(j+1)*(length_fragment);

		offset+=length_fragment/8;
		
		protocolos_registrados[protocolo_inferior](datagrama,pila_protocolos,length_fragment+pos,(void *)&IP_data);
	}
	
	return  OK;
}


/****************************************************************************************
* Nombre: moduloETH 									*
* Descripcion: Esta funcion implementa el modulo de envio Ethernet			*
* Argumentos: 										*
*  -datagrama: datagrama a enviar							*
*  -pila_protocolos: conjunto de protocolos a seguir					*
*  -longitud: bytes que componen el datagrama						*
*  -parametros: Parametros necesario para el envio este protocolo			*
* Retorno: OK/ERROR									*
****************************************************************************************/

uint8_t moduloETH(uint8_t* datagrama, uint16_t* pila_protocolos,uint64_t longitud,void *parametros){

	uint8_t pos=0;
	printf("moduloETH(fisica) %s %d.\n",__FILE__,__LINE__);
	uint8_t trama[ETH_FRAME_MAX]={0};
	uint8_t ETH_src[ETH_ALEN];
	Parametros ETH_data=*((Parametros*)parametros);
	uint16_t protocolo_inferior=pila_protocolos[3];
	uint16_t MTU;

	obtenerMTUInterface(interface, &MTU);

	if (longitud>MTU)
	{
		printf("Tamaño demasiado grande para ETH\n");
		return ERROR;
	}
	struct pcap_pkthdr header;

	header.caplen=longitud+ETH_HLEN;
	printf("caplen%d\n",header.caplen);
	header.len=longitud+ETH_HLEN;
	printf("len%d\n",header.len);

	memcpy(trama, ETH_data.ETH_destino, ETH_ALEN*sizeof(uint8_t));
	pos+=ETH_ALEN*sizeof(uint8_t);
	if (obtenerMACdeInterface(interface, ETH_src) == ERROR)
		return ERROR;

	memcpy(trama+pos, ETH_src, ETH_ALEN*sizeof(uint8_t));
	pos+=ETH_ALEN*sizeof(uint8_t);

	uint16_t aux16=IP_PROTO;
	aux16=htons(aux16);
	memcpy(trama+pos, &aux16, sizeof(uint16_t));
	pos+=sizeof(uint16_t);
	
	memcpy(trama+pos, datagrama, sizeof(uint8_t)*longitud);

	pcap_dump((u_char*) pdumper, &header, trama);
	pcap_inject(descr, trama, (pos+longitud)*sizeof(uint8_t));
	

	return OK;
}


/****************************************************************************************
* Nombre: moduloICMP 									*
* Descripcion: Esta funcion implementa el modulo de envio ICMP				*
* Argumentos: 										*
*  -mensaje: mensaje a anadir a la cabecera ICMP					*
*  -pila_protocolos: conjunto de protocolos a seguir					*
*  -longitud: bytes que componen el mensaje						*
*  -parametros: Parametros necesario para el envio este protocolo			*
* Retorno: OK/ERROR									*
****************************************************************************************/

uint8_t moduloICMP(uint8_t* mensaje, uint16_t* pila_protocolos,uint64_t longitud,void *parametros){


	uint8_t pos,aux8;
	uint8_t segmento[ICMP_DATAG_MAX];
	uint8_t checksum[2];
	uint16_t aux16;

	uint16_t protocolo_inferior=pila_protocolos[1];


	Parametros ICMP_data = *((Parametros*) parametros);

	pos = 0;
	aux8 = ICMP_data.tipo;
	memcpy(segmento+pos, &aux8, sizeof(uint8_t));	
	pos += sizeof(uint8_t);

	aux8 = ICMP_data.codigo;
	memcpy(segmento+pos, &aux8, sizeof(uint8_t));	
	pos += sizeof(uint8_t);


	aux16=0;	
	memcpy(segmento+pos, &aux16, sizeof(uint16_t));
	pos+=sizeof(uint16_t);

	aux16 = htons(64);
	memcpy(segmento+pos, &aux16, sizeof(uint16_t));
	pos+=sizeof(uint16_t);

	aux16 = htons(1);
	memcpy(segmento+pos, &aux16, sizeof(uint16_t));
	pos+=sizeof(uint16_t);

	memcpy(segmento+pos, mensaje, longitud*sizeof(uint8_t));

	calcularChecksum(longitud+pos, segmento, checksum);

	//aux16=htons(0xfd06);
	memcpy(segmento+2*sizeof(uint8_t), checksum, 2*sizeof(uint8_t));

	return protocolos_registrados[protocolo_inferior](segmento,pila_protocolos,longitud+pos,parametros);
}


/***************************Funciones auxiliares a implementar***********************************/

/****************************************************************************************
* Nombre: aplicarMascara 								*
* Descripcion: Esta funcion aplica una mascara a una vector				*
* Argumentos: 										*
*  -IP: IP a la que aplicar la mascara en orden de red					*
*  -mascara: mascara a aplicar en orden de red						*
*  -longitud: bytes que componen la direccion (IPv4 == 4)				*
*  -resultado: Resultados de aplicar mascara en IP en orden red				*
* Retorno: OK/ERROR									*
****************************************************************************************/

uint8_t aplicarMascara(uint8_t* IP, uint8_t* mascara, uint32_t longitud, uint8_t* resultado){
	int i;
	
	if (IP==NULL || mascara==NULL)
		return ERROR;
	
	for (i=0;i<longitud;++i)
		resultado[i] = IP[i] & mascara[i];
	

	return OK;
}


/***************************Funciones auxiliares implementadas**************************************/

/****************************************************************************************
* Nombre: mostrarPaquete 								*
* Descripcion: Esta funcion imprime por pantalla en hexadecimal un vetor		*
* Argumentos: 										*
*  -paquete: bytes que conforman un paquete						*
*  -longitud: Bytes que componen el mensaje						*
* Retorno: OK/ERROR									*
****************************************************************************************/

uint8_t mostrarPaquete(uint8_t * paquete, uint32_t longitud){
	uint32_t i;
	printf("Paquete:\n");
	for (i=0;i<longitud;i++){
		printf("%02X ", paquete[i]);
	}
	printf("\n");
	return OK;
}


/****************************************************************************************
* Nombre: calcularChecksum							     	*
* Descripcion: Esta funcion devuelve el ckecksum tal como lo calcula IP/ICMP		*
* Argumentos:										*
*   -longitud: numero de bytes de los datos sobre los que calcular el checksum		*
*   -datos: datos sobre los que calcular el checksum					*
*   -checksum - checksum de los datos (2 bytes) en orden de red  			*
* Retorno: OK/ERROR									*
****************************************************************************************/

uint8_t calcularChecksum(uint16_t longitud, uint8_t *datos, uint8_t *checksum) {
    uint16_t word16;
    uint32_t sum=0;
    int i;
    // make 16 bit words out of every two adjacent 8 bit words in the packet
    // and add them up
    for (i=0; i<longitud; i=i+2){
        word16 = (datos[i]<<8) + datos[i+1];
        sum += (uint32_t)word16;       
    }
    // take only 16 bits out of the 32 bit sum and add up the carries
    while (sum>>16) {
        sum = (sum & 0xFFFF)+(sum >> 16);
    }
    // one's complement the result
    sum = ~sum;      
    checksum[0] = sum >> 8;
    checksum[1] = sum & 0xFF;

    return OK;
}


/***************************Funciones inicializacion implementadas*********************************/

/****************************************************************************************
* Nombre: inicializarPilaEnviar     							*
* Descripcion: inicializar la pila de red para enviar registrando los distintos modulos *
* Retorno: OK/ERROR									*
****************************************************************************************/

uint8_t inicializarPilaEnviar() {
	bzero(protocolos_registrados,MAX_PROTOCOL*sizeof(pf_notificacion));
	if(registrarProtocolo(ETH_PROTO, moduloETH, protocolos_registrados)==ERROR)
		return ERROR;
	if(registrarProtocolo(IP_PROTO, moduloIP, protocolos_registrados)==ERROR)
		return ERROR;
	if(registrarProtocolo(UDP_PROTO, moduloUDP, protocolos_registrados)==ERROR)
		return ERROR;
	if(registrarProtocolo(ICMP_PROTO, moduloICMP,protocolos_registrados)==ERROR)
		return ERROR;
	
	return OK;
}


/****************************************************************************************
* Nombre: registrarProtocolo 								*
* Descripcion: Registra un protocolo en la tabla de protocolos 				*
* Argumentos:										*
*  -protocolo: Referencia del protocolo (ver RFC 1700)					*
*  -handleModule: Funcion a llamar con los datos a enviar				*
*  -protocolos_registrados: vector de funciones registradas 				*
* Retorno: OK/ERROR 									*
*****************************************************************************************/

uint8_t registrarProtocolo(uint16_t protocolo, pf_notificacion handleModule, pf_notificacion* protocolos_registrados){
	if(protocolos_registrados==NULL ||  handleModule==NULL){		
		printf("Error: registrarProtocolo(): entradas nulas.\n");
		return ERROR;
	}
	else
		protocolos_registrados[protocolo]=handleModule;
	return OK;
}


/****************************************************************************************
* Nombre: read_from_file 								*
* Descripcion: Lee los datos de un fichero 				*
* Argumentos:										*
*  -path: ruta
*  -max_size: tamaño máximo a leer
*  -data: puntero al array de datos		*
* Retorno: OK/ERROR 									*
*****************************************************************************************/

uint8_t read_from_file(const char* path, const size_t max_size, char* data)
{
	FILE* f = NULL;

	f = fopen(path, "r");

	if(f == NULL || fgets(data, max_size, f) == NULL)
		return ERROR;

	return OK;
}