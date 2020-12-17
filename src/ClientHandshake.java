/**
 * Client side of the handshake.
 */
import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.net.Socket;
import java.io.IOException;
import java.security.Key;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Base64;

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
    public static byte[] sessionKey;
    public static byte[] sessionIV;

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
                // Logger.log(certificateString);
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

    public void getSessionParameter(String privateKeyClientFilename) throws IOException {
        this.clientHandshakeMessage.recv(this.handshakeSocket);
        String messageType = clientHandshakeMessage.getParameter("MessageType");
        if ("Session".equals(messageType)) {
            String sessionKeyEncodedString = clientHandshakeMessage.getParameter("SessionKey");
            String sessionIVEncodedString = clientHandshakeMessage.getParameter("SessionIV");

            byte[] sessionKeyEncoded = Base64.getDecoder().decode(sessionKeyEncodedString.getBytes());
            byte[] sessionIVEncoded = Base64.getDecoder().decode(sessionIVEncodedString.getBytes());

            Logger.log("keyE: " + new String(sessionKeyEncoded));
            Logger.log("ivE: " + new String(sessionIVEncoded));

            // get the private Key
            Key privateKey = HandshakeCrypto.getPrivateKeyFromKeyFile(privateKeyClientFilename);

            sessionKey = HandshakeCrypto.decrypt(sessionKeyEncoded, privateKey);
            sessionIV = HandshakeCrypto.decrypt(sessionIVEncoded, privateKey);
            sessionHost = clientHandshakeMessage.getParameter("SessionHost");
            sessionPort = Integer.parseInt(clientHandshakeMessage.getParameter("SessionPort"));

        } else {
            throw new IOException("Not good messageType parameter.");
        }
    }
}
