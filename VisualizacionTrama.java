import java.io.IOException;
import org.pcap4j.core.PcapNativeException;
import org.pcap4j.core.PcapHandle;
import org.pcap4j.core.NotOpenException;
import org.pcap4j.core.PcapNetworkInterface.PromiscuousMode;
import org.pcap4j.core.PcapNetworkInterface;
import org.pcap4j.util.NifSelector;
import org.pcap4j.core.Pcaps;
import org.pcap4j.util.ByteArrays;

@SuppressWarnings("javadoc")
public class VisualizacionTrama{

  private static final String COUNT_KEY = VisualizacionTrama.class.getName() + ".count";
  private static final int COUNT = Integer.getInteger(COUNT_KEY, 5);

  private static final String READ_TIMEOUT_KEY = VisualizacionTrama.class.getName() + ".readTimeout";
  private static final int READ_TIMEOUT = Integer.getInteger(READ_TIMEOUT_KEY, 10); // [ms]

  private static final String SNAPLEN_KEY = VisualizacionTrama.class.getName() + ".snaplen";
  private static final int SNAPLEN = Integer.getInteger(SNAPLEN_KEY, 65536); // [bytes]

  private static final String BUFFER_SIZE_KEY = VisualizacionTrama.class.getName() + ".bufferSize";
  private static final int BUFFER_SIZE = Integer.getInteger(BUFFER_SIZE_KEY, 1 * 1024 * 1024); // [bytes]

  private static final String NIF_NAME_KEY = VisualizacionTrama.class.getName() + ".nifName";
  private static final String NIF_NAME = System.getProperty(NIF_NAME_KEY);

  private VisualizacionTrama() {}

  public static void main(String[] args) throws PcapNativeException, NotOpenException {

    System.out.println(COUNT_KEY + ": " + COUNT);
    System.out.println(READ_TIMEOUT_KEY + ": " + READ_TIMEOUT);
    System.out.println(SNAPLEN_KEY + ": " + SNAPLEN);
    System.out.println(BUFFER_SIZE_KEY + ": " + BUFFER_SIZE);
    System.out.println(NIF_NAME_KEY + ": " + NIF_NAME);
    System.out.println("\n");

    PcapNetworkInterface nif;
    
    if (NIF_NAME != null)
      nif = Pcaps.getDevByName(NIF_NAME);
    else {
        
      try {
        nif = new NifSelector().selectNetworkInterface();
      }
      catch (IOException e) {
        System.out.println("ERROR:  No se ha podido obtener la lista de interfaces de red disponibles:");
        e.printStackTrace();
        return;
      }

      if (nif == null)
        return;
    }
    
    System.out.println("\nSe ha instalado correctamente NPCAP!\n La interfaz seleccionada es " + nif.getName() + " y su descripcion es " + nif.getDescription() + "\n\n");
    
    PcapHandle handle = new PcapHandle.Builder(nif.getName())
            .snaplen(SNAPLEN)
            .promiscuousMode(PromiscuousMode.PROMISCUOUS)
            .timeoutMillis(READ_TIMEOUT)
            .bufferSize(BUFFER_SIZE)
            .build();
    
    int num = 0;
    
    while (num < COUNT) {
      byte[] packet = handle.getNextRawPacket();

      if (packet != null){
        System.out.println("\n" + handle.getTimestamp());
        //System.out.println(ByteArrays.toHexString(packet, " ") + "\n");

        for(int i = 1; i <= packet.length; i++){
          System.out.printf("%02X ", packet[i-1]);
                
          if (i % 8 == 0)
            System.out.println(" ");
        }
                    
        System.out.println("");              
        num++;
      }
    }
  }
}