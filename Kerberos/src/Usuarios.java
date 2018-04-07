
import java.security.Key;
import java.text.SimpleDateFormat;
import java.util.Calendar;
import java.util.Date;
import javax.crypto.spec.SecretKeySpec;



public class Usuarios {
    
    private String nombre;
    private Key claveUsuario;
    private AES aes;
    private static final String ALGO = "AES";

    public Usuarios(String nombre, byte clave []) throws Exception {
        this.nombre = nombre;
        this.claveUsuario = generateKey(clave);
        this.aes = new AES();
    }
    
    public String cifrarMensaje(Key clave, String mensaje) throws Exception{
        return this.aes.encrypt(mensaje, clave);
    }
    
    public String descifrarMensaje(Key clave, String mensaje) throws Exception{
        return this.aes.decrypt(mensaje, clave);
    }
    
    public String generarMensajeAutenticacion() throws Exception{
        Date tiempo = new Date();
        String envio = ""+tiempo.getTime();
        
        String mensaje = nombre +","+ envio;
        return cifrarMensaje(claveUsuario, nombre);
    }
    
    public String generarMensajeTGT(String tgt, String servicio){
        return tgt+"!!!"+servicio;
    }

    private static Key generateKey(byte keyValue []) throws Exception {
        return new SecretKeySpec(keyValue, ALGO);
    }
}
