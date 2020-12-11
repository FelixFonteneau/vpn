import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.security.SecureRandom;

public class SessionKey {

    private SecretKey secretKey;
    private static final String ALGO = "AES";
    private static final String FORMAT = "";

    /**
     * Create a key with a length
     * @param keylength the length in bits
     */
    public SessionKey(Integer keylength) {

        // getting the number of bytes by rounding up
        int byteLength = (int) Math.ceil(keylength / 8.);

        byte[] keyBytes = new byte[byteLength];

        // generating random key
        new SecureRandom().nextBytes(keyBytes);

        // creating the secret key
        this.secretKey = new SecretKeySpec(keyBytes, ALGO);
    }

    /**
     * Create a session key from a key existing in a byte array
     * @param keybytes the key
     */
    public SessionKey(byte[] keybytes) {
        this.secretKey = new SecretKeySpec(keybytes, ALGO);
    }

    /**
     * @return The secret key of the session key
     */
    public SecretKey getSecretKey() {
        return this.secretKey;
    }

    /**
     * @return The key in format of a byte array.
     */
    public byte[] getKeyBytes() {
        return this.secretKey.getEncoded();
    }
}

