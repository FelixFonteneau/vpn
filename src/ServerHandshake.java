/**
 * Server side of the handshake.
 */

import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.net.InetAddress;
import java.net.Socket;
import java.net.ServerSocket;
import java.io.IOException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;

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
                return (X509Certificate) fact.generateCertificate(is);
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
            String targetHost = handshakeMessage.getParameter("TargetHost");
            String targetPort = handshakeMessage.getParameter("TargetPort");
            Logger.log("Forward request : " + targetHost + ", " + targetPort);
        } else {
            Logger.log("bad message: " + messageType);
            throw new IOException("Not good messageType parameter.");
        }
    }
}
