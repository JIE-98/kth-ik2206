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
 
import javax.crypto.spec.IvParameterSpec;
import java.io.ByteArrayInputStream;
import java.io.FileNotFoundException;
import java.lang.Integer;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.InetSocketAddress;
import java.io.IOException;
import java.io.FileInputStream;
import java.util.Arrays;
import java.util.Base64;

public class ForwardServer
{
    private static final boolean ENABLE_LOGGING = true;
    public static final int DEFAULTSERVERPORT = 2206;
    public static final String DEFAULTSERVERHOST = "localhost";
    public static final String PROGRAMNAME = "ForwardServer";
    private static Arguments arguments;


    private ServerSocket handshakeSocket;
    
    private ServerSocket listenSocket;
    private String targetHost;
    private int targetPort;

    private X509Certificate caCert;
    private X509Certificate clientCert;
    private X509Certificate serverCert;
    private PublicKey clientKey;

    private static byte[] iv_o;
    private static byte[] sessionKey_o;

    /**
     * Do handshake negotiation with client to authenticate, learn 
     * target host/port, etc.
     */
    private void doHandshake() throws Exception {

        Socket clientSocket = handshakeSocket.accept();
        String clientHostPort = clientSocket.getInetAddress().getHostAddress() + ":" + clientSocket.getPort();
        Logger.log("Incoming handshake connection from " + clientHostPort);

        /* This is where the handshake should take place */
        //$ java ForwardServer --handshakeport=2206 --usercert=server.pem--cacert=ca.pem --key=server-private.der

        String caCert_file = arguments.get("cacert");
        String serverCert_file = arguments.get("usercert");
        caCert = getCert(caCert_file);
        serverCert = getCert(serverCert_file);

        ////////////////// [1] receive hello from client
        HandshakeMessage rec_hello = new HandshakeMessage();
        rec_hello.recv(clientSocket);
        if (rec_hello.getParameter("MessageType").equals("ClientHello")){
            clientCert = decodeCert(rec_hello.getParameter("Certificate"));
            new VerifyCertificate(clientCert, caCert);

            clientKey = clientCert.getPublicKey();

            System.out.println("[1] receive hello from client");
        }
        else{
            System.out.println("server error [1] receive hello from client");
        }

        ///////////////// [2] send server hello
        HandshakeMessage hello_server = new HandshakeMessage();
        hello_server.putParameter("MessageType","ServerHello");
        hello_server.putParameter("Certificate",encodeCert(serverCert));
        hello_server.send(clientSocket);
        System.out.println("[2] send server hello");

        ///////////[3] receive forward target port
        HandshakeMessage rec_forward = new HandshakeMessage();
        rec_forward.recv(clientSocket);
        if (rec_forward.getParameter("MessageType").equals("Forward")){
            targetHost = rec_forward.getParameter("TargetHost");
            targetPort = Integer.parseInt(rec_forward.getParameter("TargetPort"));
            System.out.print("[3] receive forward target port");

        }
        else{
            System.out.println("server error [3] receive forward target port");
        }


        ////////////[4] send sessionkey
        SessionKey session = new SessionKey(128);

        SecureRandom random = new SecureRandom();
        byte[] iv_b = new byte[16];
        random.nextBytes(iv_b);
                // System.out.println("random 16byte = " + iv_b);
        byte[] secretKey_b = session.getSecretKey().getEncoded();
        byte[] secretKey_b_e = HandshakeCrypto.encrypt(secretKey_b,clientKey);   // encrypt with client public key
        byte[] iv_b_e = HandshakeCrypto.encrypt(iv_b,clientKey);
                 // System.out.println("iv encoded = "+ iv_b_e);

        String secretKey = Base64.getEncoder().encodeToString(secretKey_b_e);   //encode to string
        String sessionIV = Base64.getEncoder().encodeToString(iv_b_e);

        iv_o = iv_b;
        sessionKey_o = secretKey_b;

        //test
        System.out.println("key"+ Arrays.toString(sessionKey_o));
        System.out.println("iv"+ Arrays.toString(iv_o));
        System.out.println("iv string = "+sessionIV);


        HandshakeMessage session_server = new HandshakeMessage();
        session_server.putParameter("MessageType","Session");
        session_server.putParameter("SessionKey",secretKey);
        session_server.putParameter("SessionIV",sessionIV);
        session_server.putParameter("SessionHost",Handshake.sessionHost);
        session_server.putParameter("SessionPort",Integer.toString(Handshake.sessionPort));
        session_server.send(clientSocket);

        clientSocket.close();

        System.out.println("[4] send sessionkey");
        System.out.println("[Handshake success]");



        /*
         * Fake the handshake result with static parameters. 
         */

        /* listenSocket is a new socket where the ForwardServer waits for the 
         * client to connect. The ForwardServer creates this socket and communicates
         * the socket's address to the ForwardClient during the handshake, so that the 
         * ForwardClient knows to where it should connect (ServerHost/ServerPort parameters).
         * Here, we use a static address instead (serverHost/serverPort). 
         * (This may give "Address already in use" errors, but that's OK for now.)
         */
        listenSocket = new ServerSocket();
        listenSocket.bind(new InetSocketAddress(Handshake.sessionHost, Handshake.sessionPort));

        /* The final destination. The ForwardServer sets up port forwarding
         * between the listensocket (ie., ServerHost/ServerPort) and the target.
         */
      //  targetHost = Handshake.targetHost;
      //  targetPort = Handshake.targetPort;
    }

    private X509Certificate getCert(String filename) throws CertificateException, FileNotFoundException {
            CertificateFactory ca1 = CertificateFactory.getInstance("X.509");
            FileInputStream is1 = new FileInputStream(filename);
            return (X509Certificate) ca1.generateCertificate(is1);

    }

    //decode certificate from string to x509
    private X509Certificate decodeCert(String encodedCert) throws CertificateException {
        CertificateFactory ca1 = CertificateFactory.getInstance("X.509");
        ByteArrayInputStream is1 = new ByteArrayInputStream(Base64.getDecoder().decode(encodedCert));
        return (X509Certificate) ca1.generateCertificate(is1);
    }
    //encode certificate, from x509 to string
    private String encodeCert(X509Certificate cert) throws CertificateEncodingException {
        return Base64.getEncoder().encodeToString(cert.getEncoded());
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
        try {
            handshakeSocket = new ServerSocket(port);
        } catch (IOException ioe) {
            throw new IOException("Unable to bind to port " + port + ": " + ioe);
        }

        log("Nakov Forward Server started on TCP port " + port);
 
        // Accept client connections and process them until stopped
        while(true) {
            ForwardServerClientThread forwardThread;
            
            doHandshake();

            forwardThread = new ForwardServerClientThread(this.listenSocket, this.targetHost, this.targetPort, sessionKey_o,iv_o);
            forwardThread.start();
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
        arguments.setDefault("handshakeport", Integer.toString(DEFAULTSERVERPORT));
        arguments.setDefault("handshakehost", DEFAULTSERVERHOST);
        arguments.loadArguments(args);
        
        ForwardServer srv = new ForwardServer();
        srv.startForwardServer();
    }
 
}
