/**
 * Port forwarding client. Forward data
 * between two TCP ports. Based on Nakov TCP Socket Forward Server 
 * and adapted for IK2206.
 *
 * See original copyright notice below.
 * (c) 2018 Peter Sjodin, KTH
 */

/**
 * Nakov TCP Socket Forward Server - freeware
 * Version 1.0 - March, 2002
 * (c) 2001 by Svetlin Nakov - http://www.nakov.com
 */

 
import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.io.ByteArrayInputStream;
import java.io.FileNotFoundException;
import java.lang.IllegalArgumentException;
import java.lang.Integer;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.io.IOException;
import java.io.FileInputStream;
import java.security.spec.InvalidKeySpecException;
import java.util.Arrays;
import java.util.Base64;

public class ForwardClient
{
    private static final boolean ENABLE_LOGGING = true;
    public static final int DEFAULTSERVERPORT = 2206;
    public static final String DEFAULTSERVERHOST = "localhost";
    public static final String PROGRAMNAME = "ForwardClient";

    private static Arguments arguments;
    private static int sessionPort;
    private static String sessionHost;

    private static X509Certificate caCert;
    private static X509Certificate clientCert;
    private static X509Certificate serverCert;
    private static PrivateKey privateKey;

    private static String targethost;
    private static String targetport;
    //private static String sessionHost;
    //private static String sessionPort;


 //   private static byte[] sessionKey_b;
    private static byte[] iv;
    private static byte[] sessionKey;


    private static void doHandshake() throws IOException, CertificateException, InvalidKeySpecException, NoSuchAlgorithmException, IllegalBlockSizeException, InvalidKeyException, NoSuchPaddingException, BadPaddingException {

        /* Connect to forward server server */
        System.out.println("Connect to " +  arguments.get("handshakehost") + ":" + Integer.parseInt(arguments.get("handshakeport")));
        Socket socket = new Socket(arguments.get("handshakehost"), Integer.parseInt(arguments.get("handshakeport")));

        /* This is where the handshake should take place */
        //$ java ForwardClient --handshakehost=portfw.kth.se  --handshakeport=2206 \
        //    --targethost=server.kth.se --targetport=6789 \
        //    --usercert=client.pem --cacert=ca.pem --key=client-private.der


        String caCert_file = arguments.get("cacert");
        String clientCert_file = arguments.get("usercert");
        caCert = getCert(caCert_file);
        clientCert = getCert(clientCert_file);
        targethost = arguments.get("targethost");
        targetport = arguments.get("targetport");
        privateKey = HandshakeCrypto.getPrivateKeyFromKeyFile(arguments.get("key"));

        //[1] send hello to server
        HandshakeMessage hello_client = new HandshakeMessage();
        hello_client.putParameter("MessageType","ClientHello");
        hello_client.putParameter("Certificate",encodeCert(clientCert));
        hello_client.send(socket);
        System.out.println("[1] send hello to server");

        ///////////[2] receive hello from server
        HandshakeMessage rec_hello = new HandshakeMessage();
        rec_hello.recv(socket);
        if (rec_hello.getParameter("MessageType").equals("ServerHello")){
            serverCert = decodeCert(rec_hello.getParameter("Certificate"));
            new VerifyCertificate(serverCert, caCert);
            System.out.println("[2] receive hello from server");
        }
        else{
            System.out.println("client error [2] receive hello from server ");
        }

        ///////////[3] forward target port
        HandshakeMessage forward_target = new HandshakeMessage();
        forward_target.putParameter("MessageType","Forward");
        forward_target.putParameter("TargetHost",targethost);
        forward_target.putParameter("TargetPort",targetport);
        forward_target.send(socket);
        System.out.println("[3] forward target port");

        ///////////[4] rec sessionkey
        HandshakeMessage rec_session = new HandshakeMessage();
        rec_session.recv(socket);
        if (rec_session.getParameter("MessageType").equals("Session")){

            sessionHost = rec_session.getParameter("SessionHost");
                     System.out.println("serverport = "+rec_session.getParameter("ServerPort"));
                    System.out.println("sessionport = "+rec_session.getParameter("SessionPort"));
                System.out.println("sessionhost = "+rec_session.getParameter("SessionHost"));
                System.out.println("serverhost = "+rec_session.getParameter("ServerHost"));
            sessionPort = Integer.parseInt(rec_session.getParameter("SessionPort"));
            byte[] sessionKey_b_e = Base64.getDecoder().decode(rec_session.getParameter("SessionKey"));
            sessionKey = HandshakeCrypto.decrypt(sessionKey_b_e,privateKey);

            byte[] iv_b_e = Base64.getDecoder().decode(rec_session.getParameter("SessionIV"));
            iv =  HandshakeCrypto.decrypt(iv_b_e,privateKey);
            System.out.println("[4] rec sessionkey ");
        }
        else{
            System.out.println("client error [4] rec sessionkey ");
        }

        //test
        System.out.println("key = "+ Arrays.toString(sessionKey));
        System.out.println("iv = "+ Arrays.toString(iv));
        //System.out.println("iv");
       // System.out.println(Integer.toHexString(iv[0]));


       socket.close();

        System.out.println("Handshake done");

        /*
         * Fake the handshake result with static parameters.
         */

        /* This is to where the ForwardClient should connect. 
         * The ForwardServer creates a socket
         * dynamically and communicates the address (hostname and port number)
         * to ForwardClient during the handshake (ServerHost, ServerPort parameters).
         * Here, we use a static address instead. 
         */
        //

       // sessionHost = Handshake.sessionHost;
       // sessionPort = Handshake.sessionPort;
    }

    private static X509Certificate getCert(String filename) throws FileNotFoundException, CertificateException {
        CertificateFactory ca1 = CertificateFactory.getInstance("X.509");
        FileInputStream is1 = new FileInputStream(filename);
        return (X509Certificate) ca1.generateCertificate(is1);
    }

    //decode certificate, from string to x509
    private static X509Certificate decodeCert(String encodedCert) throws CertificateException {
        CertificateFactory ca1 = CertificateFactory.getInstance("X.509");
        ByteArrayInputStream is1 = new ByteArrayInputStream(Base64.getDecoder().decode(encodedCert));
        return (X509Certificate) ca1.generateCertificate(is1);
    }

    //encode certificate, from x509 to string
    private static String encodeCert(X509Certificate cert) throws CertificateEncodingException {
        return Base64.getEncoder().encodeToString(cert.getEncoded());
    }









    /*
     * Let user know that we are waiting
     */
    private static void tellUser(ServerSocket listensocket) throws UnknownHostException {
        System.out.println("Client forwarder to target " + arguments.get("targethost") + ":" + arguments.get("targetport"));
        System.out.println("Waiting for incoming connections at " +
                           InetAddress.getLocalHost().getHostAddress() + ":" + listensocket.getLocalPort());
    }
        
    /*
     * Set up client forwarder.
     * Run handshake negotiation, then set up a listening socket and wait for user.
     * When user has connected, start port forwarder thread.
     */
    static public void startForwardClient() throws IOException, CertificateException, NoSuchPaddingException, NoSuchAlgorithmException, IllegalBlockSizeException, BadPaddingException, InvalidKeyException, InvalidKeySpecException, InvalidAlgorithmParameterException {

        doHandshake();

        // Wait for client. Accept one connection.

        ForwardServerClientThread forwardThread;
        ServerSocket listensocket;
        
        /* Create a new socket. This is to where the user should connect.
         * ForwardClient sets up port forwarding between this socket
         * and the ServerHost/ServerPort learned from the handshake */
        listensocket = new ServerSocket();
        /* Let the system pick a port number */
        listensocket.bind(null); 
        /* Tell the user, so the user knows where to connect */ 
        tellUser(listensocket);

        Socket clientSocket = listensocket.accept();
        String clientHostPort = clientSocket.getInetAddress().getHostAddress() + ":" + clientSocket.getPort();
        log("Accepted client from " + clientHostPort);
            
        forwardThread = new ForwardServerClientThread(clientSocket, sessionHost, sessionPort,sessionKey,iv);
        forwardThread.start();
    }

    /**
     * Prints given log message on the standart output if logging is enabled,
     * otherwise ignores it
     */
    public static void log(String aMessage)
    {
        if (ENABLE_LOGGING)
           System.out.println(aMessage);
    }
 
    static void usage() {
        String indent = "";
        System.err.println(indent + "Usage: " + PROGRAMNAME + " options");
        System.err.println(indent + "Where options are:");
        indent += "    ";
        System.err.println(indent + "--targethost=<hostname>");
        System.err.println(indent + "--targetport=<portnumber>");        
        System.err.println(indent + "--handshakehost=<hostname>");
        System.err.println(indent + "--handshakeport=<portnumber>");        
        System.err.println(indent + "--usercert=<filename>");
        System.err.println(indent + "--cacert=<filename>");
        System.err.println(indent + "--key=<filename>");                
    }
    
    /**
     * Program entry point. Reads arguments and run
     * the forward server
     */
    public static void main(String[] args) throws CertificateException, NoSuchAlgorithmException, IOException, BadPaddingException, IllegalBlockSizeException, NoSuchPaddingException, InvalidKeyException, InvalidKeySpecException, InvalidAlgorithmParameterException {
        try {
            arguments = new Arguments();
            arguments.setDefault("handshakeport", Integer.toString(DEFAULTSERVERPORT));
            arguments.setDefault("handshakehost", DEFAULTSERVERHOST);
            arguments.loadArguments(args);
            if (arguments.get("targetport") == null || arguments.get("targethost") == null) {
                throw new IllegalArgumentException("Target not specified");
            }
        } catch(IllegalArgumentException ex) {
            System.out.println(ex);
            usage();
            System.exit(1);
        }
        startForwardClient();
    }
}
