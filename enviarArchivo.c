#include <stdlib.h>
#include <stdio.h>
#include <pcap.h>

int main()
{
    pcap_t *input_fp;
    pcap_t *output_fp;
    struct pcap_pkthdr *header;
    const u_char *pkt_data;
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_if_t *alldevs;
    pcap_if_t *d;
    int i = 0, inum = 0;
    
    /* Abrir el archivo pcap de entrada */
    input_fp = pcap_open_offline("paquetesCapturados.pcap", errbuf);
    if (input_fp == NULL) {
        fprintf(stderr, "Error al abrir el archivo pcap de entrada: %s\n", errbuf);
        return -1;
    }
    
    /* Buscamos todos los dispositivos */
    if (pcap_findalldevs(&alldevs, errbuf) == -1)
    {
        fprintf(stderr, "Error en la funcion pcap_findalldevs: %s\n", errbuf);
        return -1;
    }
    
    printf("\n.: Lista de interfaces :.\n\n");
    /* Mostramos la lista obtenida */
    for (d = alldevs; d; d = d->next)
    {
        printf("%d. %s", ++i, d->name);
        if (d->description)
            printf(" (%s)\n", d->description);
        else
            printf(" (No hay descripci?n disponible)\n");
    }
    
    if (i == 0)
    {
        printf("\nNo se encontraron interfaces! Asegurece que tiene instalado NPCAP.\n");
        return -1;
    }
    
    printf("\nIngrese el numero de la interfaz (1-%d): ", i);
    scanf("%d", &inum);
    
    if (inum < 1 || inum > i)
    {
        printf("\nN?mero de interfaz fuera de rango.\n");
        /* Liberar la lista de dispositivos */
        pcap_freealldevs(alldevs);
        return -1;
    }
    
    /* Saltar al adaptador seleccionado */
    for (d = alldevs, i = 0; i < inum - 1; d = d->next, i++);
    
    /* Abrir la interfaz de red para enviar los paquetes (2da) */
    output_fp = pcap_open_live(d->name, 65536, 1, 1000, errbuf);
    
	if (output_fp == NULL) {
        fprintf(stderr, "Error al abrir la interfaz de red: %s\n", errbuf);
        pcap_close(input_fp);
        return -1;
    }
    
    /* Leer cada paquete del archivo pcap de entrada */
    while (pcap_next_ex(input_fp, &header, &pkt_data) == 1) {
        /* Enviar el paquete utilizando pcap_sendpacket */
        if (pcap_sendpacket(output_fp, pkt_data, header->len) != 0) {
            fprintf(stderr, "Error al enviar el paquete: %s\n", pcap_geterr(output_fp));
            pcap_close(input_fp);
            pcap_close(output_fp);
            return -1;
        }
        else {
            printf("Paquete enviado\n");
        }
    }
    
    pcap_close(input_fp);
    pcap_close(output_fp);
    
    printf("Se han enviado todos los paquetes del archivo pcap.\n");
    
    return 0;
}
