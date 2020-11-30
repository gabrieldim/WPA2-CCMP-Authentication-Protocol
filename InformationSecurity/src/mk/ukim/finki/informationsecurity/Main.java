package mk.ukim.finki.informationsecurity;

public class Main {
    public static void main(String[] args) throws Exception {

            //Author:  GABRIEL DIMITRIEVSKI

        /*Pochetni potrebni vrednosti za ponatamnoshno testiranje na kodot*/
        String sourceMAC = "DC-DC-43-EC-21-34";
        String destinationMAC = "EC-EC-05-CC-06-33";
        String key = "trinaeset1111";
        String message = "TESTING THE ALGORITHM ===> INFORMATION SECUTIRY <===";
        ClearTextFrame clearTextFrame = new ClearTextFrame(message,sourceMAC,destinationMAC); /*objekt od ClearTextFrame*/

        System.out.println("Encrypted frame:");/*printanje na enkripcijata*/
        EncryptedFrame encryptedFrame = WP2SimulationECB.encryptFrame(clearTextFrame,key);/*objekt od EncryptedFrame*/
        System.out.println(encryptedFrame);

        System.out.println("\n");

        System.out.println("Derypted frame:");
        ClearTextFrame decryptedFrame = WP2SimulationECB.decryptFrame(encryptedFrame,key);
        System.out.println(decryptedFrame);/*printanje na dekripcijata*/
    }
}
