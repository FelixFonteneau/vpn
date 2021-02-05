/**
 * Server side of the handshake.
 */

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.PublicKey;
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
    private ServerSocket sessionSocket;
    private String sessionHost;
    private int sessionPort;
    private Socket handshakeSocket;

    /* The final destination -- simulate handshake with constants */
    private String targetHost = "localhost";
    private int targetPort = 6789;

    /* Security parameters key/iv should also go here. Fill in! */
    private static int SESSION_KEY_LENGTH = 128;
    private SessionEncrypter sessionEncrypter;
    private X509Certificate clientCertificate;

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
    }

    /**
     * Get the first message of a client and get its certificate.
     * @return certificate
     * @throws IOException exception
     */
    public X509Certificate getClientCertificate() throws IOException{
        HandshakeMessage handshakeMessage = new HandshakeMessage();

        handshakeMessage.recv(this.handshakeSocket);

        Logger.log("ClientHello message:");
        handshakeMessage.list(System.out);
        Logger.log("\n");

        try {
            String messageType = handshakeMessage.getParameter("MessageType");
            if (messageType.equals("ClientHello")){
                CertificateFactory fact = CertificateFactory.getInstance("X.509");
                String certificateEncoded64String = handshakeMessage.getParameter("Certificate");

                InputStream is = new ByteArrayInputStream(Base64.getDecoder().decode(certificateEncoded64String));
                // Logger.log("Client Certificate: " + certificateString);
                clientCertificate = (X509Certificate) fact.generateCertificate(is);
                return clientCertificate;
            } else {
                throw new IOException("Not good messageType parameter.");
            }
        } catch (CertificateException e) {
            throw new IOException(e.getMessage());
        }
    }

    /**
     * Send the server's reply with its certificate
     * @param certificate64Encoded certificate
     * @throws IOException exception
     */
    public void sendServerCertificate(String certificate64Encoded) throws IOException{
        HandshakeMessage handshakeMessage = new HandshakeMessage();

        handshakeMessage.putParameter("MessageType", "ServerHello");
        handshakeMessage.putParameter("Certificate", certificate64Encoded);
        handshakeMessage.send(this.handshakeSocket);

        Logger.log("ServerHello message:");
        handshakeMessage.list(System.out);
        Logger.log("\n");
    }

    /**
     * Get the client forward request and check if everything is fine
     * @throws IOException exception
     */
    public void getClientForwardRequest() throws IOException {
        HandshakeMessage handshakeMessage = new HandshakeMessage();

        handshakeMessage.recv(this.handshakeSocket);

        Logger.log("Forward message:");
        handshakeMessage.list(System.out);
        Logger.log("\n");


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

    /**
     * Send the reply about port forwarding, sned all the parameter to establish the session.
     * @throws IOException exception.
     */
    public void sendSessionParameter() throws IOException {
        HandshakeMessage handshakeMessage = new HandshakeMessage();

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

        Logger.log("Session message:");
        handshakeMessage.list(System.out);
        Logger.log("\n");
    }

    public void closeConnection(){
        try { sessionSocket.close(); } catch (IOException e){}
    }

    public ServerSocket getSessionSocket() {
        return sessionSocket;
    }

    public String getSessionHost() {
        return sessionHost;
    }

    public int getSessionPort() {
        return sessionPort;
    }

    public Socket getHandshakeSocket() {
        return handshakeSocket;
    }

    public String getTargetHost() {
        return targetHost;
    }

    public int getTargetPort() {
        return targetPort;
    }

    public SessionEncrypter getSessionEncrypter() {
        return sessionEncrypter;
    }
}
