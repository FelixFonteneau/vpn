/**
 * Port forwarding server. Forward data
 * between two TCP ports. Based on Nakov TCP Socket Forward Server
 * and adapted for IK2206.
 *
 * Original copyright notice below.
 * (c) 2018 Peter Sjodin, KTH
 */

/**
 * Nakov TCP Socket Forward Server - freeware
 * Version 1.0 - March, 2002
 * (c) 2001 by Svetlin Nakov - http://www.nakov.com
 */

import java.lang.Integer;
import java.net.InetAddress;
import java.security.cert.X509Certificate;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.UnknownHostException;
import java.io.IOException;
import java.util.Base64;

public class ForwardServer
{
    private static final boolean ENABLE_LOGGING = true;
    public static final int DEFAULTHANDSHAKEPORT = 2206;
    public static final String DEFAULTHANDSHAKEHOST = "localhost";
    public static final String PROGRAMNAME = "ForwardServer";
    private static Arguments arguments;

    private ServerHandshake serverHandshake;
    private ServerSocket handshakeListenSocket;

    /**
     * Do handshake negotiation with client to authenticate and learn
     * target host/port, etc.
     */
    private void doHandshake(Socket handshakeSocket) throws UnknownHostException, IOException, Exception {
        serverHandshake = new ServerHandshake(handshakeSocket);

        // receive new request
        X509Certificate clientCertificate = serverHandshake.getClientCertificate();
        // Logger.log("Server receive handshake. Certificate: " + clientCertificate);

        // verify the certificate
        X509Certificate caCertificate = VerifyCertificate.getCertificate(arguments.get("cacert"));
        Logger.log("Client's certificate verified.");
        VerifyCertificate.verifyCertificate(clientCertificate, caCertificate);

        // send server's certificate
        String serverCertificateEncodedString = Base64.getEncoder().encodeToString(VerifyCertificate.getCertificate(arguments.get("usercert")).getEncoded());
        serverHandshake.sendServerCertificate(serverCertificateEncodedString);

        // get client forward request
        serverHandshake.getClientForwardRequest();

        // check if the host is joinable
        if(!InetAddress.getByName(ServerHandshake.targetHost).isReachable(1000)){
            throw new UnknownHostException("Host " + ServerHandshake.targetHost + " not joinable");
        }

        // generate session parameter and send to the client
        serverHandshake.sendSessionParameter();
    }

    /**
     * Starts the forward server - binds on a given port and starts serving
     */
    public void startForwardServer()
    //throws IOException
        throws Exception
    {

        // Bind server on given TCP port
        int port = Integer.parseInt(arguments.get("handshakeport"));
        ServerSocket handshakeListenSocket;
        try {
            handshakeListenSocket = new ServerSocket(port);
        } catch (IOException ioex) {
            throw new IOException("Unable to bind to port " + port + ": " + ioex);
        }

        log("Nakov Forward Server started on TCP port " + handshakeListenSocket.getLocalPort());

        // Accept client connections and process them until stopped
        while(true) {
            try{
                Socket handshakeSocket = handshakeListenSocket.accept();
                String clientHostPort = handshakeSocket.getInetAddress().getHostName() + ":" +
                        handshakeSocket.getPort();
                Logger.log("Incoming handshake connection from " + clientHostPort);

                doHandshake(handshakeSocket);
                handshakeSocket.close();

                /*
                 * Set up port forwarding between an established session socket to target host/port.
                 *
                 */

                ForwardServerThread forwardThread;
                forwardThread = new ForwardServerThread(ServerHandshake.sessionSocket,
                        ServerHandshake.targetHost,
                        ServerHandshake.targetPort,
                        ServerHandshake.sessionEncrypter.getKeyBytes(),
                        ServerHandshake.sessionEncrypter.getIVBytes());

                forwardThread.start();
            } catch (IOException e){
                e.printStackTrace();
            }
        }
    }

    /**
     * Prints given log message on the standart output if logging is enabled,
     * otherwise ignores it
     */
    public void log(String aMessage)
    {
        if (ENABLE_LOGGING)
           System.out.println(aMessage);
    }

    static void usage() {
        String indent = "";
        System.err.println(indent + "Usage: " + PROGRAMNAME + " options");
        System.err.println(indent + "Where options are:");
        indent += "    ";
        System.err.println(indent + "--handshakehost=<hostname>");
        System.err.println(indent + "--handshakeport=<portnumber>");
        System.err.println(indent + "--usercert=<filename>");
        System.err.println(indent + "--cacert=<filename>");
        System.err.println(indent + "--key=<filename>");
    }

    /**
     * Program entry point. Reads settings, starts check-alive thread and
     * the forward server
     */
    public static void main(String[] args)
        throws Exception
    {
        arguments = new Arguments();
        arguments.setDefault("handshakeport", Integer.toString(DEFAULTHANDSHAKEPORT));
        arguments.setDefault("handshakehost", DEFAULTHANDSHAKEHOST);
        arguments.loadArguments(args);

        if (arguments.get("usercert") == null || arguments.get("cacert") == null) {
            throw new IllegalArgumentException("Certificates not specified");
        }
        if (arguments.get("key") == null) {
            throw new IllegalArgumentException("Private key not specified");
        }

        ForwardServer srv = new ForwardServer();
        srv.startForwardServer();
    }

}
