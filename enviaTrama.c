#include <stdlib.h>
#include <stdio.h>
#include <pcap.h>

int main()
{
    pcap_t *fp;
    u_char packet[100];
    int i = 0;
    int k = 0;
    pcap_if_t *alldevs;
    pcap_if_t *d;
    int inum;
    char errbuf[PCAP_ERRBUF_SIZE];
    
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
            printf(" (No hay descripci�n disponible)\n");
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
        printf("\nNumero de interfaz fuera de rango.\n");
        /* Liberar la lista de dispositivos */
        pcap_freealldevs(alldevs);
        return -1;
    }
    
    /* Saltar al adaptador seleccionado */
    for (d = alldevs, i = 0; i < inum - 1; d = d->next, i++);
    
    if ((fp = (pcap_t *)pcap_open(d->name, // nombre del dispositivo
                                100,        // porci�n del paquete que vamos a enviar, en este caso solo los primeros 100 bytes
                                1,          // modo promiscuo  (Cualquier numero diferente de cero lo activa, si es 0 lo desactiva)
                                1000,       // especifica el tiempo de espera del b�fer del paquete, como un valor no negativo, en milisegundos.
                                NULL,       // Autenticaci�n en una maquina remota
                                errbuf      // error buffer
                                )) == NULL)
    {
        //fprintf(stderr,"\nNo es posible abrir esta interfaz de red. %s no tiene soporte para WinPcap\n", d->name);
        printf("\nNo es posible abrir esta interfaz de red. %s no tiene soporte para WinPcap\n", d->name);

        /* Liberar la lista de dispositivos */
        pcap_freealldevs(alldevs);
        return -1;
    }
    
    /* En este punto no necesitamos m�s la lista de dispositivos, entonces la liberamos */
	pcap_freealldevs(alldevs);
    
    /* Suponiendo que estamos en Ethernet, configuramos la mac destino como ff:ff:ff:ff:ff:ff */
    for (i = 0; i < 6; i++)
        packet[i] = 0xff;
    
    /* Establecemos la mac origen como 2:2:2:2:2:2 */
    for (i = 6; i < 12; i++)
        packet[i] = 2;
    
    /* Establecemos el tipo de la trama */
    packet[12] = 0x08;
    packet[13] = 0x00;
    
    /* Llenamos el resto de la trama con un dato 'random' */
    for (i = 14; i < 100; i++)
        packet[i] = i % 256;
    
    /* Enviamos el paquete */
    for (k = 0; k < 10; k++)
    {
        if (pcap_sendpacket(fp, packet, 100) != 0)
        {
            fprintf(stderr, "\nError al enviar el paquete: \n", pcap_geterr(fp));
            return -1;
        }
        else
        {
            printf("Enviando trama (%d/10)...\n", k + 1);
        }
    }
    
    printf("\nSe ha enviado por completo las tramas");
    
    return 0;
}
