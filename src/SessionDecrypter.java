import javax.crypto.Cipher;
import javax.crypto.CipherInputStream;
import javax.crypto.spec.GCMParameterSpec;
import java.io.InputStream;


public class SessionDecrypter {
    private SessionKey sessionKey;
    private byte[] ivBytes;

    public SessionDecrypter(byte[] keybytes, byte[] ivbytes){
        this.sessionKey = new SessionKey(keybytes);
        this.ivBytes = ivbytes;
    }

    public CipherInputStream openCipherInputStream(InputStream input){
        // create the cypher
        Cipher cipher;
        try{
            cipher = Cipher.getInstance("AES/GCM/NoPadding");
            GCMParameterSpec gcmParameterSpec = new GCMParameterSpec(128, ivBytes);
            cipher.init(Cipher.DECRYPT_MODE, this.sessionKey.getSecretKey(), gcmParameterSpec);
        } catch (Exception e){
            e.printStackTrace();
            cipher = null;
        }

        // return the CIS
        return new CipherInputStream(input, cipher);
    }
}
