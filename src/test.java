import java.util.Base64;

public class test {
    public static void main(String[] args) {
        byte[] sessionKeyEncrypted = "aaaaa".getBytes();
        String sessionKeyString = new String(Base64.getEncoder().encode(sessionKeyEncrypted));

        byte[] sessionKeyEncoded = Base64.getDecoder().decode(sessionKeyString.getBytes());


        byte[] encoded = Base64.getEncoder().encode("Hello".getBytes());
        byte[] decoded = Base64.getDecoder().decode(encoded);
        System.out.println(new String(decoded));    // Outputs "Hello"


        Logger.log("keyE: " + new String(sessionKeyEncrypted));
        Logger.log("PostKeyE: " +  new String(sessionKeyEncoded));
    }
}
