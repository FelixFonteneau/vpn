/**
 * Client side of the handshake.
 */

import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.net.Socket;
import java.io.IOException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;

public class ClientHandshake {
    private Socket handshakeSocket;
    /*
     * The parameters below should be learned by the client
     * through the handshake protocol.
     */
    private HandshakeMessage clientHandshakeMessage;

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
        this.clientHandshakeMessage = new HandshakeMessage();
    }

    public void sendCertificate(String cerficate) throws IOException {
        clientHandshakeMessage.putParameter("MessageType"	, "ClientHello");
        clientHandshakeMessage.putParameter("Certificate"		, cerficate);
        clientHandshakeMessage.send(this.handshakeSocket);
    }

    public X509Certificate getServersCertificate() throws IOException {
        try {
            this.clientHandshakeMessage.recv(this.handshakeSocket);
            String messageType = clientHandshakeMessage.getParameter("MessageType");
            if ("ServerHello".equals(messageType)) {
                CertificateFactory fact = CertificateFactory.getInstance("X.509");
                String certificateString = clientHandshakeMessage.getParameter("Certificate");
                InputStream is = new ByteArrayInputStream(certificateString.getBytes());
                Logger.log(certificateString);
                return (X509Certificate) fact.generateCertificate(is);
            } else {
                throw new IOException("Not good messageType parameter.");
            }
        } catch (CertificateException e) {
            throw new IOException(e.getMessage());
        }
    }

    public void requestPortForwarding(String targetHost, String targetPort) throws IOException {
        clientHandshakeMessage.putParameter("MessageType", "Forward");
        clientHandshakeMessage.putParameter("TargetHost", targetHost);
        clientHandshakeMessage.putParameter("TargetPort", targetPort);
        clientHandshakeMessage.send(this.handshakeSocket);
    }
}
