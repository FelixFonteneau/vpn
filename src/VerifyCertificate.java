import java.io.FileInputStream;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.*;
import java.security.cert.*;

public class VerifyCertificate {
    /*
        -Print the DN for the CA (one line)
        -Print the DN for the user (one line)
        -Verify the CA certificate
        -Verify the user certificate
        -Print "Pass" if check 3 and 4 are successful
        -Print "Fail" if any of them fails, followed by an explanatory comment of how the verification failed
        -Print "Fail" if any of them fails, followed by an explanatory comment of how the verification failed
     */

    public static X509Certificate verifyCertificateFile(String clientCertFilename, String caCertFileName) throws IOException {
        X509Certificate clientCertificate;
        // step 1
        try {
            clientCertificate = getCertificate(clientCertFilename);

            // step 2
            X509Certificate caCertificate = getCertificate(caCertFileName);

            verifyCertificate(clientCertificate, caCertificate);
        } catch (CertificateException e) {
            throw new IOException("Error while loading certificate");
        }

        return clientCertificate;
    }

    public static void verifyCertificate(X509Certificate clientCertificate,
                                         X509Certificate caCertificate) throws IOException {
        // step 3
        // verification CA self-signed
        if (! (verifySignature(caCertificate, caCertificate.getPublicKey()))){
            throw new IOException("CA signature is not valid.");
        }
        // verification CA date validity
        if (! (checkDateValidity(caCertificate))){
            throw new IOException("CA date is not valid.");
        }

        // step 4
        // verification client CA-signed
        if (! (verifySignature(clientCertificate, caCertificate.getPublicKey()))){
            throw new IOException("Client signature is not valid.");
        }
        // verification client date validity
        if (! (checkDateValidity(clientCertificate))){
            throw new IOException("Client cert signature is not valid.");
        }
    }


    public static X509Certificate getCertificate(String fileName) throws IOException, CertificateException {
        CertificateFactory fact = CertificateFactory.getInstance("X.509");
        FileInputStream is = new FileInputStream (fileName);
        return (X509Certificate) fact.generateCertificate(is);
    }

    public static String getCertificateToString(String filename) throws IOException {
        // FileInputStream is = new FileInputStream (fileName);
        Path fileName = Path.of(filename);
        return Files.readString(fileName);
    }

    public static boolean verifySignature(X509Certificate certificate, PublicKey key) {
        try {
            certificate.verify(key);
        } catch (CertificateException | InvalidKeyException | NoSuchProviderException | NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (SignatureException e) {
            return false;
        }
        return true;
    }

    public static boolean checkDateValidity(X509Certificate certificate) {
        try {
            certificate.checkValidity();
        } catch (CertificateExpiredException | CertificateNotYetValidException e) {
            return false;
        }
        return true;
    }

    public static void main(String[] args) {

        try {
            verifyCertificateFile(args[1], args[0]);
        } catch (Exception e) {
            e.printStackTrace();
        }


        X509Certificate caCert, clientCert;
        try{
            // step 1
            caCert = getCertificate(args[0]);
            System.out.println("CA DN: " + caCert.getSubjectX500Principal());

            // step 2
            clientCert = getCertificate(args[1]);
            System.out.println("User DN: " + clientCert.getSubjectX500Principal());

            // step 3
            // verification CA self-signed
            if (! (verifySignature(caCert, caCert.getPublicKey()))){
                System.out.println("Fail");
                return;
            }
            // verification CA date validity
            if (! (checkDateValidity(caCert))){
                System.out.println("Fail");
                return;
            }

            // step 4
            // verification client CA-signed
            if (! (verifySignature(clientCert, caCert.getPublicKey()))){
                System.out.println("Fail");
                return;
            }
            // verification client date validity
            if (! (checkDateValidity(clientCert))){
                System.out.println("Fail");
                return;
            }
            System.out.println("Pass");
        } catch (CertificateException e) {
            e.printStackTrace();
        } catch (IOException e){
            e.printStackTrace();
            System.err.println("File not found: " + args[0] + " or " + args[1]);
        }
        // check the arguments
        /*System.out.println("Args:");
        for (String s : args) {
            System.out.println(s);
        }*/
    }
}
