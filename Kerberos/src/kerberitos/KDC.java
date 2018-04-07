package kerberitos;


import java.security.Key;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.crypto.spec.SecretKeySpec;


public class KDC {
    private static final String ALGO = "AES";
    private static final byte[] tgsKey =
            new byte[]{'T', 'G', 'S', 'c', 'i', 't', 'a', 'S', 'e', 'c', 'r', 'e', 't', 'K', 'e', 'y'};
    protected Key ktgs;
    protected String nombres [];

    public KDC(){
        try {
            this.ktgs = generateKey(tgsKey);
        } catch (Exception ex) {
            Logger.getLogger(KDC.class.getName()).log(Level.SEVERE, null, ex);
        }
        this.nombres = new String []{"Alice","Bob","Eve"};
    }
    
    private static Key generateKey(byte keyValue []) throws Exception {
        return new SecretKeySpec(keyValue, ALGO);
    }
}
