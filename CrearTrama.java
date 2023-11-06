import java.io.IOException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import org.pcap4j.core.NotOpenException;
import org.pcap4j.core.PcapHandle;
import org.pcap4j.core.PcapNativeException;
import org.pcap4j.core.PcapNetworkInterface;
import org.pcap4j.core.PcapNetworkInterface.PromiscuousMode;
import org.pcap4j.packet.EthernetPacket;
import org.pcap4j.util.MacAddress;
import org.pcap4j.util.NifSelector;

@SuppressWarnings("javadoc")
public class CrearTrama {

  private static final String COUNT_KEY = CrearTrama.class.getName() + ".count";
  private static final int COUNT = Integer.getInteger(COUNT_KEY, 1);

  private static final String READ_TIMEOUT_KEY = CrearTrama.class.getName() + ".readTimeout";
  private static final int READ_TIMEOUT = Integer.getInteger(READ_TIMEOUT_KEY, 10); // [ms]

  private static final String SNAPLEN_KEY = CrearTrama.class.getName() + ".snaplen";
  private static final int SNAPLEN = Integer.getInteger(SNAPLEN_KEY, 65536); // [bytes]

  private static final MacAddress SRC_MAC_ADDR = MacAddress.getByName("18:47:3D:97:A4:19");

  private CrearTrama() {}

  public static void main(String[] args) throws PcapNativeException, NotOpenException {

    // Seleccionamos la interfaz de las disponibles
    PcapNetworkInterface nif;
    try {
      nif = new NifSelector().selectNetworkInterface();
    } catch (IOException e) {
      e.printStackTrace();
      return;
    }
    
    // Si no tenemos interfaz, terminamos el programa
    if (nif == null) {
      return;
    }
    
    // Imprimimos la info de la interfaz seleccionada
    System.out.println(nif.getName() + "(" + nif.getDescription() + ")");

    // Creamos el manejador tomando encuenta las macros
    PcapHandle sendHandle = nif.openLive(SNAPLEN, PromiscuousMode.PROMISCUOUS, READ_TIMEOUT);
    ExecutorService pool = Executors.newSingleThreadExecutor();

    
    try {
     
      // Creamos la trama (arreglo de bytes)
      byte[] trama = new byte[100];
      // Obtiene la MAC Origen de la interfaz de red selecionada
      byte[]mco = nif.getLinkLayerAddresses().get(0).getAddress();
      
      
      for(int k = 0; k < 6; k++){
        trama[k]=(byte)0xFF; //Asignamos la MAC Destino
        trama[k+6] = mco[k]; //Asignamos la MAC Origen
      }
      
      // Asignamos el Campo Tipo
      trama[12] = (byte)0x16;
      trama[13] = (byte)0x01;

      // Mensaje a mandar 
      String msj = "un mensaje corto";
      // Serializamos el mensaje
      byte[] tmp = msj.getBytes();

      // Pegamos el mensaje en la trama que vamos a enviar
      for(int k = 0; k < tmp.length; k++)
        trama[14+k] = tmp[k];
     
      // Mostramos el mensaje
      System.out.println("trama a ser enviada:");
      for(int k = 0; k < trama.length ;k++)
        System.out.printf("%02X ",trama[k]);

      try{
        //Creamos el objeto 'paquete' con la trama que creamos anteriormente
        EthernetPacket pp = EthernetPacket.newPacket(trama, 0, trama.length);

        //Mandamos 10 copias del mensaje
        for (int i = 0; i < 10; i++) {
          sendHandle.sendPacket(pp);
          
          try {
            Thread.sleep(1000);
          } catch (InterruptedException e) {
            System.out.printf("Se");
          }
        }

      }catch(Exception e){e.printStackTrace();}

    }finally {
      if (sendHandle != null && sendHandle.isOpen()) 
        sendHandle.close();
    }
  }
}