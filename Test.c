#include <stdlib.h>
#include <stdio.h>
#include <pcap.h>

int main(int argc, char **argv)
{
	pcap_if_t *alldevs;
	char errbuf[PCAP_ERRBUF_SIZE];
	
	/* Buscamos todas las tarjetas de red disponibles en nuestro equipo */
	if(pcap_findalldevs(&alldevs, errbuf) == -1)
		printf("ERROR:  No se ha podido obtener la lista de interfaces de red disponibles ");
	else
		printf("Se ha instalado correctamente NPCAP");
	
    return 0;
}
