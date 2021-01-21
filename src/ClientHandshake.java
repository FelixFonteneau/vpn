/**
 * Client side of the handshake.
 */

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.Socket;
import java.security.PrivateKey;
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

    /* Session host/port  */
    public static String sessionHost = "localhost";
    public static int sessionPort = 12345;
    public static byte[] sessionKey;
    public static byte[] sessionIV;

    /**
     * Run client handshake protocol on a handshake socket.
     * Here, we do nothing, for now.
     */
    public ClientHandshake(Socket handshakeSocket) {
        this.handshakeSocket = handshakeSocket;
    }

    /**
     * Send the first message with the certificate
     * @param certificate64Encoded Certificate
     * @throws IOException exception
     */
    public void sendCertificate(String certificate64Encoded) throws IOException {
        HandshakeMessage clientHandshakeMessage = new HandshakeMessage();
        clientHandshakeMessage.putParameter("MessageType", "ClientHello");
        clientHandshakeMessage.putParameter("Certificate", certificate64Encoded);
        clientHandshakeMessage.send(this.handshakeSocket);

        Logger.log("ClientHello message:");
        clientHandshakeMessage.list(System.out);
        Logger.log("\n");
    }

    /**
     * Get the server's reply with its certificate
     * @return certificate
     * @throws IOException exception
     */
    public X509Certificate getServersCertificate() throws IOException {
        HandshakeMessage clientHandshakeMessage = new HandshakeMessage();

        try {
            clientHandshakeMessage.recv(this.handshakeSocket);

            Logger.log("ServerHello message:");
            clientHandshakeMessage.list(System.out);
            Logger.log("\n");

            String messageType = clientHandshakeMessage.getParameter("MessageType");
            if ("ServerHello".equals(messageType)) {
                CertificateFactory fact = CertificateFactory.getInstance("X.509");
                String certificateEncoded64String = clientHandshakeMessage.getParameter("Certificate");
                InputStream is = new ByteArrayInputStream(Base64.getDecoder().decode(certificateEncoded64String));
                // Logger.log(certificateString);
                return (X509Certificate) fact.generateCertificate(is);
            } else {
                throw new IOException("Not good messageType parameter.");
            }
        } catch (CertificateException e) {
            throw new IOException(e.getMessage());
        }
    }

    /**
     * Send the second message to request port forwarding
     * @param targetHost the target host address
     * @param targetPort the target host port
     * @throws IOException exception
     */
    public void requestPortForwarding(String targetHost, String targetPort) throws IOException {
        HandshakeMessage clientHandshakeMessage = new HandshakeMessage();

        clientHandshakeMessage.putParameter("MessageType", "Forward");
        clientHandshakeMessage.putParameter("TargetHost", targetHost);
        clientHandshakeMessage.putParameter("TargetPort", targetPort);
        clientHandshakeMessage.send(this.handshakeSocket);

        Logger.log("Forward message:");
        clientHandshakeMessage.list(System.out);
        Logger.log("\n");
    }

    /**
     * Get the server's reply about the forwarding, retrieve the session parameters.
     * @param privateKeyClientFilename the private key
     * @throws IOException exception
     */
    public void getSessionParameter(String privateKeyClientFilename) throws IOException {
        HandshakeMessage clientHandshakeMessage = new HandshakeMessage();

        clientHandshakeMessage.recv(this.handshakeSocket);

        Logger.log("Session message:");
        clientHandshakeMessage.list(System.out);
        Logger.log("\n");

        String messageType = clientHandshakeMessage.getParameter("MessageType");
        if ("Session".equals(messageType)) {
            String sessionKeyEncodedString = clientHandshakeMessage.getParameter("SessionKey");
            String sessionIVEncodedString = clientHandshakeMessage.getParameter("SessionIV");

            byte[] sessionKeyEncoded = Base64.getDecoder().decode(sessionKeyEncodedString.getBytes());
            byte[] sessionIVEncoded = Base64.getDecoder().decode(sessionIVEncodedString.getBytes());

            // get the private Key
            PrivateKey privateKey = HandshakeCrypto.getPrivateKeyFromKeyFile(privateKeyClientFilename);

            sessionKey = HandshakeCrypto.decrypt(sessionKeyEncoded, privateKey);
            sessionIV = HandshakeCrypto.decrypt(sessionIVEncoded, privateKey);
            sessionHost = clientHandshakeMessage.getParameter("SessionHost");
            sessionPort = Integer.parseInt(clientHandshakeMessage.getParameter("SessionPort"));

        } else {
            throw new IOException("Not good messageType parameter.");
        }
    }
}
