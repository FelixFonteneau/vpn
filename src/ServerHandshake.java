/**
 * Server side of the handshake.
 */

import javax.crypto.SecretKey;
import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.net.InetAddress;
import java.net.Socket;
import java.net.ServerSocket;
import java.io.IOException;
import java.security.PublicKey;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Base64;

public class ServerHandshake {
    /*
     * The parameters below should be learned by the server
     * through the handshake protocol.
     */

    /* Session host/port, and the corresponding ServerSocket  */
    public static ServerSocket sessionSocket;
    public static String sessionHost;
    public static int sessionPort;
    private HandshakeMessage handshakeMessage;
    private Socket handshakeSocket;

    /* The final destination -- simulate handshake with constants */
    public static String targetHost = "localhost";
    public static int targetPort = 6789;

    /* Security parameters key/iv should also go here. Fill in! */
    public static int SESSION_KEY_LENGTH = 128;
    public static SessionEncrypter sessionEncrypter;
    public static X509Certificate clientCertificate;
    /**
     * Run server handshake protocol on a handshake socket.
     * Here, we simulate the handshake by just creating a new socket
     * with a preassigned port number for the session.
     */
    public ServerHandshake(Socket handshakeSocket) throws IOException {
        sessionSocket = new ServerSocket(12345);
        sessionHost = sessionSocket.getInetAddress().getHostName();
        sessionPort = sessionSocket.getLocalPort();
        this.handshakeSocket = handshakeSocket;
        this.handshakeMessage = new HandshakeMessage();
    }

    public X509Certificate getClientCertificate() throws IOException{
        this.handshakeMessage.recv(this.handshakeSocket);
        try {
            String messageType = handshakeMessage.getParameter("MessageType");
            if (messageType.equals("ClientHello")){
                CertificateFactory fact = CertificateFactory.getInstance("X.509");
                String certificateString = handshakeMessage.getParameter("Certificate");
                InputStream is = new ByteArrayInputStream(certificateString.getBytes());
                // Logger.log(certificateString);
                clientCertificate = (X509Certificate) fact.generateCertificate(is);
                return clientCertificate;
            } else {
                throw new IOException("Not good messageType parameter.");
            }
        } catch (CertificateException e) {
            throw new IOException(e.getMessage());
        }
    }

    public void sendServerCertificate(String certificate) throws IOException{
        handshakeMessage.putParameter("MessageType"	, "ServerHello");
        handshakeMessage.putParameter("Certificate"		, certificate);
        handshakeMessage.send(this.handshakeSocket);
    }

    public void getClientForwardRequest() throws IOException {
        this.handshakeMessage.recv(this.handshakeSocket);
        String messageType = handshakeMessage.getParameter("MessageType");
        if (messageType.equals("Forward")){
            targetHost = handshakeMessage.getParameter("TargetHost");
            targetPort = Integer.parseInt(handshakeMessage.getParameter("TargetPort"));
            Logger.log("Forward request : " + targetHost + ", " + targetPort);
        } else {
            Logger.log("bad message: " + messageType);
            throw new IOException("Not good messageType parameter.");
        }
    }

    public void sendSessionParameter() throws IOException {

        // generate session key/iv
        sessionEncrypter = new SessionEncrypter(SESSION_KEY_LENGTH);

        // encode this parameter with client's public key
        PublicKey clientPublicKey1 = clientCertificate.getPublicKey();
        PublicKey clientPublicKey2 = HandshakeCrypto.getPublicKeyFromCertFile("client.pem");


        byte[] sessionKeyEncrypted = HandshakeCrypto.encrypt(sessionEncrypter.getKeyBytes(), clientPublicKey2);
        byte[] sessionIVEncrypted = HandshakeCrypto.encrypt(sessionEncrypter.getIVBytes(), clientPublicKey2);

        String sessionKeyString = Base64.getEncoder().encodeToString(sessionKeyEncrypted);
        String sessionIVString = Base64.getEncoder().encodeToString(sessionIVEncrypted);

        // send session information
        handshakeMessage.putParameter("MessageType", "Session");
        handshakeMessage.putParameter("SessionKey", sessionKeyString);
        handshakeMessage.putParameter("SessionIV", sessionIVString);
        handshakeMessage.putParameter("SessionHost", sessionHost);
        handshakeMessage.putParameter("SessionPort", Integer.toString(sessionPort));
        handshakeMessage.send(this.handshakeSocket);
    }
}
