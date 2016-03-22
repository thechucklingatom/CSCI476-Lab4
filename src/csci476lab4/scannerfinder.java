/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package csci476lab4;

import java.util.Arrays;
import java.util.HashMap;
import java.util.Set;
import org.jnetpcap.Pcap;
import org.jnetpcap.packet.JPacket;
import org.jnetpcap.packet.JPacketHandler;
import org.jnetpcap.protocol.network.Ip4;
import org.jnetpcap.protocol.tcpip.Http;
import org.jnetpcap.protocol.tcpip.Tcp;

/**
 *
 * @author thech_000
 */
public class scannerfinder {

    /**
     * @param args the command line arguments
     */
    public static void main(String[] args) {
        // TODO code application logic here
        
        final String FILENAME = args[0];  
        final StringBuilder errbuf = new StringBuilder();  
        HashMap<String, int[]> map = new HashMap<>();
  
        //from tutorial
        final Pcap pcap = Pcap.openOffline(FILENAME, errbuf);  
        if (pcap == null) {  
            System.err.println(errbuf); // Error is stored in errbuf if any  
            return;  
        }
        
        //LOOP_INFINITE goes until EOF
        pcap.loop(Pcap.LOOP_INFINITE, new JPacketHandler<StringBuilder>() {  
            
            final Tcp tcp = new Tcp();    
            
            final Ip4 ip = new Ip4();
  
            /** 
             * Our custom handler that will receive all the packets libpcap will 
             * dispatch to us. This handler is inside a libpcap loop and will receive 
             * exactly 10 packets as we specified on the Pcap.loop(10, ...) line 
             * above. 
             *  
             * @param packet 
             *          a packet from our capture file 
             * @param errbuf 
             *          our custom user parameter which we chose to be a StringBuilder 
             *          object, but could have chosen anything else we wanted passed 
             *          into our handler by libpcap 
             */  
            @Override
            public void nextPacket(JPacket packet, StringBuilder errbuf) {  
                
                //if it has both headers grab them both
                //Potentially unneeded but the tutorial reccomends it
                if (packet.hasHeader(Tcp.ID) && packet.hasHeader(Ip4.ID)) {   
                    packet.getHeader(tcp); 
                    packet.getHeader(ip);

                }  
 
                //double checking
                if (packet.hasHeader(tcp) && packet.hasHeader(ip)) {  
                    
                    //if it is SYN but not ack'd it is an outgoing packet
                    if (tcp.flags_SYN() && !tcp.flags_ACK()){
                        //string key since java defaults to signed bytes
                        //it is stored as unsigned bytes so have to convert
                        String key = "";
                        for(int i = 0; i < ip.source().length; i++){
                            //convert to unsigned byte (@returns int)
                            //converted to string by java auto casting
                            key += (ip.source()[i] & 0xFF);
                            if(i != 3){
                                key += ".";
                            }
                        }
                        
                        if (map.containsKey(key)){
                            //if the key exists add one to sent syn packets
                            map.put(key, new int[]{map.get(key)[0] + 1,  map.get(key)[1]});
                        }else{
                            //otherwise make a new one with 1 sent syn packet
                            map.put(key, new int[]{1, 0});
                        }
                    //if syn'd and ack'd it is the other machines response.
                    }else if (tcp.flags_SYN() && tcp.flags_ACK()){
                        //string key since java defaults to signed bytes
                        //it is stored as unsigned bytes so have to convert
                        String key = "";
                        for(int i = 0; i < ip.destination().length; i++){
                            //convert to unsigned byte (@returns int)
                            //converted to string by java auto casting
                            key += (ip.destination()[i] & 0xFF);
                            if(i != 3){
                                key += ".";
                            }
                        }
                        
                        if (map.containsKey(key)){
                            //if the map has that ip as suspicious, log an ack
                            map.put(key, new int[]{map.get(key)[0],  map.get(key)[1] + 1});
                        }
                    }
                }   
            }  
  
        }, errbuf);  
        
        //to loop though maps keys.
        Set<String> keys = map.keySet();
        
        //loop to print out the suspicous ips
        for(String key : keys){
            try{
                //@throws ArithmeticException when map.get(key)[1] = 0
                if(map.get(key)[0] / map.get(key)[1] >= 3){
                    System.out.printf("IP %s with 3x as many unacked packets\n", key);
                }
            }catch (ArithmeticException e){
                //print all the ips that never got any ack, maybe attacking
                //probably not though.
                System.out.printf("IP %s with 0 acked packets\n", key);
            }
        }
        
        //if there were any errors print them just in case
        System.err.println(errbuf);
        
    }
    
}
