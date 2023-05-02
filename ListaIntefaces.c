#ifdef _MSC_VER
/*
No queremos las advertencias sobre las antiguas y obsoletas funciones CRT inseguras,
ya que estos ejemplos también se pueden compilar bajo *nix.
*/
#define _CRT_SECURE_NO_WARNINGS
#endif

#include <pcap.h>

int main()
{
	printf("\n.: Lista de interfaces :.\n\n");
	pcap_if_t *alldevs;
	pcap_if_t *device;
	
	int i = 0;
    int select;
	
    pcap_t *adhandle;
	char errbuf[PCAP_ERRBUF_SIZE];
	
	/* Recuperar la lista de dispositivos */
	if (pcap_findalldevs(&alldevs, errbuf) == -1)
	{
	    fprintf(stderr, "Error en pcap_findalldevs: %s\n", errbuf);
	    exit(1);
	}
	
	/* Imprimir la lista */
	for (device = alldevs; device; device = device->next)
	{
	    printf("%d. %s", ++i, device->name);
	    if (device->description)
	        printf(" (%s)\n", device->description);
	    else
	        printf(" (No hay descripción disponible)\n");
	}
	
	if (i == 0)
	{
	    printf("\n¡No se encontraron interfaces! Asegúrese de que WinPcap esté instalado.\n");
	    return -1;
	}
	
	printf("\nIngrese el numero de la interfaz (1-%d): ", i);
	scanf("%d", &select);
	
	if (select < 1 || select > i)
	{
	    printf("\nNúmero de interfaz fuera de rango.\n");
	    /* Liberar la lista de dispositivos */
	    pcap_freealldevs(alldevs);
	    return -1;
	}
	
	/* Saltar al adaptador seleccionado */
	for (device = alldevs, i = 0; i < select - 1; device = device->next, i++);
	
	printf("\nInterfaz seleccionada: \n\tName: %s \n\tDescription: %s",device->name,device->description);
	
}