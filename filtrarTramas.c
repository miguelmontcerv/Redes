#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/*
	Se utiliza la librería libpcap para capturar y filtrar paquetes de red.
	El programa permite al usuario seleccionar una interfaz de red,
	capturar paquetes y aplicar un filtro a los paquetes capturados.
	Los paquetes que pasen el filtro se imprimen en pantalla y se guardan en un archivo de captura.
*/

/* Prototipo de funciones */
void manejador_paquetes(u_char *dumpfile, const struct pcap_pkthdr *header, const u_char *pkt_data);

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
    struct bpf_program fp; // Estructura para almacenar el filtro compilado

    /* Recuperar la lista de dispositivos */
    if (pcap_findalldevs(&alldevs, errbuf) == -1) {
        printf("Error en pcap_findalldevs: %s\n", errbuf);
        exit(1);
    }

    /* Imprimir la lista de dispositivos */
    for (device = alldevs; device; device = device->next) {
        printf("%d. %s", ++i, device->name);
        if (device->description)
            printf(" (%s)\n", device->description);
        else
            printf(" (No hay descripción disponible)\n");
    }

    if (i == 0) {
        printf("\n¡No se encontraron interfaces! Asegúrese de que WinPcap esté instalado.\n");
        return -1;
    }

    printf("\nIngrese el número de la interfaz (1-%d): ", i);
    scanf("%d", &select);

    if (select < 1 || select > i) {
        printf("\nNúmero de interfaz fuera de rango.\n");
        /* Liberar la lista de dispositivos */
        pcap_freealldevs(alldevs);
        return -1;
    }

    /* Saltar al adaptador seleccionado */
    for (device = alldevs, i = 0; i < select - 1; device = device->next, i++)
        ;

    printf("\nInterfaz seleccionada:\n\tName: %s\n\tDescription: %s\n", device->name, device->description);

    /* Abrir la interfaz de red para capturar paquetes */
    if ((adhandle = pcap_open_live(device->name, 65536, 1, 1000, errbuf)) == NULL) {
        printf("\nNo es posible abrir esta interfaz de red. %s no tiene soporte para WinPcap\n", device->name);

        /* Liberar la lista de dispositivos */
        pcap_freealldevs(alldevs);
        return -1;
    }

    /* Abrir el archivo de captura */
    dumpfile = pcap_dump_open(adhandle, "paquetesCapturados.pcap");
    if (dumpfile == NULL) {
        printf("\nError al abrir el archivo de salida\n");
        return -1;
    }

    printf("\nComenzando a escuchar a %s...\n", device->description);

    /* Liberar la lista de dispositivos */
    pcap_freealldevs(alldevs);

    char filter_exp[100];
    printf("\nIngrese la expresión de filtro (por ejemplo, 'tcp port 80'): ");
    scanf("%s", filter_exp);

    /* Compilar el filtro */
    if (pcap_compile(adhandle, &fp, filter_exp, 0, PCAP_NETMASK_UNKNOWN) == -1) {
        printf("\nError al compilar el filtro: %s\n", pcap_geterr(adhandle));
        return -1;
    }

    /* Aplicar el filtro */
    if (pcap_setfilter(adhandle, &fp) == -1) {
        printf("\nError al aplicar el filtro: %s\n", pcap_geterr(adhandle));
        return -1;
    }

    /* Iniciar el bucle de captura */
    if (pcap_loop(adhandle, 5, manejador_paquetes, (unsigned char *)dumpfile) == -1) {
        printf("\nError en el bucle de captura: %s\n", pcap_geterr(adhandle));
        return -1;
    }

    /* Cerrar la captura y el archivo de captura */
    pcap_close(adhandle);
    pcap_dump_close(dumpfile);

    return 0;
}

/* Función de callback invocada por libpcap para cada paquete entrante */
void manejador_paquetes(u_char *dumpfile, const struct pcap_pkthdr *header, const u_char *pkt_data)
{
    int i = 0, j = 0;

    // Guardar el paquete en el archivo de captura
    pcap_dump(dumpfile, header, pkt_data);

	printf("\n\n\tMAC Destino:\n\t");
	for(j = 0; j < 6; j++)
	   printf("%02X: ",pkt_data[j]);

	printf("\n\n\tMAC Origen:\n\t");
	for(j = 6; j < 12; j++)
	   printf("%02X: ",pkt_data[j]);   
	
    unsigned short tipo = (pkt_data[12] * 256) + pkt_data[13];

    printf("\n\n\tTipo: %d   %02X %02X \n",tipo,pkt_data[12],pkt_data[13]);
    
    printf("\n\tResto de la trama:\n\t");
	for(i = 14, j = 0; i < header->caplen; i++, j++){
		if(j % 8 == 0)
			printf("\n\t");
		printf("%02X: ", pkt_data[i]);    
	} 	
}