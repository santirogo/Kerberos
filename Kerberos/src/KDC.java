
import java.security.Key;
import javax.crypto.spec.SecretKeySpec;


public class KDC {
    private static final String ALGO = "AES";
    private static final byte[] tgsKey =
            new byte[]{'T', 'G', 'S', 'c', 'i', 't', 'a', 'S', 'e', 'c', 'r', 'e', 't', 'K', 'e', 'y'};
    protected Key ktgs;

    public KDC() throws Exception {
        this.ktgs = generateKey(tgsKey);
    }
    
    private static Key generateKey(byte keyValue []) throws Exception {
        return new SecretKeySpec(keyValue, ALGO);
    }
}
