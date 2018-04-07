
import java.security.Key;
import javax.crypto.spec.SecretKeySpec;



public class Usuarios {
    private String nombre;
    private Key claveUsuario;
    private static final String ALGO = "AES";

    public Usuarios(String nombre, byte clave []) throws Exception {
        this.nombre = nombre;
        this.claveUsuario = generateKey(clave);
    }

    private static Key generateKey(byte keyValue []) throws Exception {
        return new SecretKeySpec(keyValue, ALGO);
    }
}
