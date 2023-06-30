#ifdef _MSC_VER
/* No queremos las advertencias sobre las antiguas y obsoletas funciones CRT inseguras,
	ya que estos ejemplos también se pueden compilar bajo *nix. */
#define _CRT_SECURE_NO_WARNINGS
#endif
#include <pcap.h>

/*
	https://www.tcpdump.org/manpages/pcap_open_live.3pcap.html
	https://www.tcpdump.org/manpages/pcap_loop.3pcap.html
*/

void packet_handler(u_char *param, const struct pcap_pkthdr *header, const u_char *pkt_data);
int main()
{
	printf("\n.: Lista de interfaces :.\n\n");
	pcap_if_t *alldevs;
	pcap_if_t *device;
	
	pcap_t *adhandle;
    pcap_dumper_t *dumpfile;
	
	int i = 0;
    int select;

	char errbuf[PCAP_ERRBUF_SIZE];
	
	/* Recuperar la lista de dispositivos */
	if (pcap_findalldevs(&alldevs, errbuf) == -1)
	{
	    //fprintf(stderr, "Error en pcap_findalldevs: %s\n", errbuf);
		printf("Error en pcap_findalldevs: %s\n", errbuf);
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
	
	if ((adhandle= pcap_open_live(device->name,	// nombre del dispositivo
							 65536,			// snaplen especifica la duración de la instantánea que se establecerá en el identificador.
											// 65536 garantiza que todo el paquete se capturará en todos las direcciones MAC.
							 1,				// modo promiscuo  (Cualquier numero diferente de cero lo activa, si es 0 lo desactiva)
							 1000,			// especifica el tiempo de espera del búfer del paquete, como un valor no negativo, en milisegundos.
							 errbuf			// error buffer
							 )) == NULL)
							 //La función regresa NULL si algo salió mal
	{
		//fprintf(stderr,"\nNo es posible abrir esta interfaz de red. %s no tiene soporte para WinPcap\n", d->name);
		printf("\nNo es posible abrir esta interfaz de red. %s no tiene soporte para WinPcap\n", device->name);

		/* Liberar la lista de dispositivos */
		pcap_freealldevs(alldevs);
		return -1;
	}
	
	/* En el caso contrario, abrimos el archivo donde escribiremos los datos y creamos una variable que lo almacenará */
    dumpfile = pcap_dump_open(adhandle, "paquetesCapturados.pcap");

    if(dumpfile==NULL)
    {
        //fprintf(stderr,"\nError al abrir el archivo de salida\n");
		printf("\nError al abrir el archivo de salida\n");
        return -1;
    }
	printf("\nComenzando a escuchar a %s...\n", device->description);
	
	/* En este punto no necesitamos más la lista de dispositivos, entonces la liberamos */
	pcap_freealldevs(alldevs);
	
	/* Comenzamos la captura */
	pcap_loop(adhandle, 1, packet_handler, (unsigned char *)dumpfile);
	
	pcap_close(adhandle);
	return 0;
}


/* funcion de callback invocada por libpcap para cada paquete entrante */
void packet_handler(u_char *dumpfile, const struct pcap_pkthdr *header, const u_char *pkt_data)
{
	int i = 0;

    printf("\n\tTrama capturada:\n\t");
	for(i = 0; i < header->caplen; i++){
		if(i % 8 == 0)
			printf("\n\t");
    	printf("%02X: ", pkt_data[i]);    
	}
}
