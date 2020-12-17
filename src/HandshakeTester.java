import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Base64;

public class HandshakeTester {
    static String PRIVATEKEYFILE = "client-private.der"; // "private-pkcs8.der";
    static String CERTFILE = "client.pem"; // "cert-pkcs1.pem";
    static String PLAINTEXT = "Time flies like an arrow. Fruit flies like a banana.";
    static String ENCODING = "UTF-8"; /* For converting between strings and byte arrays */

    static public void main(String[] args) throws Exception {

        /* Extract key pair */
        PublicKey publickey = HandshakeCrypto.getPublicKeyFromCertFile(CERTFILE);
        PrivateKey privatekey = HandshakeCrypto.getPrivateKeyFromKeyFile(PRIVATEKEYFILE);

        /* Encode string as bytes */
        byte[] plaininputbytes = PLAINTEXT.getBytes(ENCODING);
        /* Encrypt it */
        byte[] cipher = HandshakeCrypto.encrypt(plaininputbytes, publickey);

        String sessionKeyString = Base64.getEncoder().encodeToString(cipher);
        byte[] sessionKeyEncoded = Base64.getDecoder().decode(sessionKeyString);




        /* Then decrypt back */
        byte[] plainoutputbytes = HandshakeCrypto.decrypt(sessionKeyEncoded, privatekey);
        /* Decode bytes into string */
        String plainoutput = new String(plainoutputbytes, ENCODING);
        if (plainoutput.equals(PLAINTEXT)) {
            System.out.println("Pass. Input and output strings are the same: \"" + PLAINTEXT + "\"");
        }
        else {
            System.out.println("Fail. Expected \"" + PLAINTEXT + "\", but got \"" + plainoutput + "\'");
        }
    }
}
