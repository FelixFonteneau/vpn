/**
 * Client side of the handshake.
 */

import java.net.Socket;
import java.io.IOException;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;

public class ClientHandshake {
    private Socket handshakeSocket;
    /*
     * The parameters below should be learned by the client
     * through the handshake protocol.
     */


    /* Session host/port  */
    public static String sessionHost = "localhost";
    public static int sessionPort = 12345;

    /* Security parameters key/iv should also go here. Fill in! */

    /**
     * Run client handshake protocol on a handshake socket.
     * Here, we do nothing, for now.
     */
    public ClientHandshake(Socket handshakeSocket) throws IOException {
        this.handshakeSocket = handshakeSocket;
    }

    public void sendCertificate(Certificate cerficate) {

    }

    public X509Certificate getServersCertificate() {

        return null;
    }

    private static String toStringCertificat(Certificate certificate){
        return "";
    }
}
