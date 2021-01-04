import javax.crypto.Cipher;
import javax.crypto.CipherOutputStream;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import java.io.OutputStream;
import java.security.SecureRandom;

import static javax.crypto.Cipher.ENCRYPT_MODE;

public class SessionEncrypter {
    private static final int IV_LENGTH = 16;
    private SessionKey sessionKey;
    private byte[] ivBytes;


    public SessionEncrypter(Integer keylength) {
        this.sessionKey = new SessionKey(keylength);
        this. ivBytes = new byte[IV_LENGTH];
        new SecureRandom().nextBytes(ivBytes);
    }

    public SessionEncrypter(byte[] keybytes, byte[] ivbytes) {
        this.sessionKey =  new SessionKey(keybytes);
        this.ivBytes = ivbytes;
    }

    public byte[] getKeyBytes() {
        return this.sessionKey.getKeyBytes();
    }
    public byte[] getIVBytes() {
        return ivBytes;
    }

    public CipherOutputStream openCipherOutputStream(OutputStream output){
        // create the cypher
        Cipher cipher;
        try{
            cipher = Cipher.getInstance("AES/CTR/NoPadding");
            IvParameterSpec ivParameterSpec = new IvParameterSpec(ivBytes);
            cipher.init(ENCRYPT_MODE, this.sessionKey.getSecretKey(), ivParameterSpec);
        } catch (Exception e){
            e.printStackTrace();
            cipher = null;
        }

        // return the COS
        return new CipherOutputStream(output, cipher);
    }
}
