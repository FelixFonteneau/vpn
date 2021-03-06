import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.io.*;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;


public class HandshakeCrypto {
    private static final String PKCS1_BEGINING_PATTERN = "-----BEGIN";
    private static final String PKCS1_END_PATTERN = "-----END";


    public static byte[] encrypt(byte[] plaintext, Key key){
        Cipher cipher = null;
        byte[] cipherByte = null;

        try {
            cipher = Cipher.getInstance("RSA");
        } catch (NoSuchAlgorithmException | NoSuchPaddingException e) {
            e.printStackTrace();
        }
        try {
            cipher.init(Cipher.ENCRYPT_MODE, key);
        } catch (InvalidKeyException e) {
            e.printStackTrace();
        }

        try {
            cipherByte = cipher.doFinal(plaintext);
        } catch (IllegalBlockSizeException | BadPaddingException e) {
            e.printStackTrace();
        }
        return cipherByte;
    }

    public static byte[] decrypt(byte[] ciphertext, Key key){
        byte[] result = null;
        Cipher cipher = null;
        try {
            cipher = Cipher.getInstance("RSA");
        } catch (NoSuchAlgorithmException | NoSuchPaddingException e) {
            e.printStackTrace();
        }
        try {
            cipher.init(Cipher.DECRYPT_MODE, key);
        } catch (InvalidKeyException e) {
            e.printStackTrace();
        }
        try {
            result = cipher.doFinal(ciphertext);
        } catch (IllegalBlockSizeException | BadPaddingException e) {
            e.printStackTrace();
        }
        return result;
    }

    public static PublicKey getPublicKeyFromCertFile(String certfile){
        CertificateFactory fact = null;
        PublicKey publicKey = null;
        try {
            fact = CertificateFactory.getInstance("X.509");
            FileInputStream is = new FileInputStream(certfile);
            X509Certificate certificate = null;
            certificate = (X509Certificate) fact.generateCertificate(is);
            publicKey = certificate.getPublicKey();
        } catch (CertificateException | FileNotFoundException e) {
            e.printStackTrace();
        }
        return publicKey;
    }

    public static PrivateKey getPrivateKeyFromKeyFile(String keyfile) throws IOException{
        byte[] keyBytes = Files.readAllBytes(Paths.get(keyfile));

        try{
            PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(keyBytes);
            KeyFactory kf = KeyFactory.getInstance("RSA");
            return kf.generatePrivate(spec);
        } catch (NoSuchAlgorithmException | InvalidKeySpecException e){
            throw new IOException(e);
        }

     //   try {
     //       KeyFactory keyFactory = KeyFactory.getInstance("RSA");
     //       byte[] keyBytes = fileToByteArray(keyfile);
     //       PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(keyBytes);
     //       return keyFactory.generatePrivate(keySpec);
     //   } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
     //       e.printStackTrace();
     //   } catch (IOException e) {
     //       System.err.println("File: " + keyfile + " not found.");
     //       e.printStackTrace();
     //   }
     //   return null;
    }



    private static byte[] fileToByteArray(String fileName) throws IOException {
        InputStream is = new FileInputStream(fileName);
        ByteArrayOutputStream buffer = new ByteArrayOutputStream();

        int nRead;
        byte[] data = new byte[16384];

        while ((nRead = is.read(data, 0, data.length)) != -1) {
            buffer.write(data, 0, nRead);
        }

        return buffer.toByteArray();
    }
}
