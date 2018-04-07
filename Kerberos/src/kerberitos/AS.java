package kerberitos;


import java.security.Key;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Calendar;
import java.util.Date;
import javax.crypto.spec.SecretKeySpec;


public class AS extends KDC{
    private AES aes;
    private String idUsuarios [];
    private String ipUsuarios [];
    private ArrayList<Key> clavesUsuarios;
    private ArrayList<Key> clavesUsuariosTGS;
    private static final String ALGO = "AES";
    
    private static final byte[] aliceKey =
            new byte[]{'A', 'l', 'i', 'c', 'i', 'a', 's', 'S', 'e', 'c', 'r', 'e', 't', 'K', 'e', 'y'};
    private static final byte[] bobKey =
            new byte[]{'B', 'o', 'b', 'c', 'i', 't', 'o', 'S', 'e', 'c', 'r', 'e', 't', 'K', 'e', 'y'};
    private static final byte[] eveKey =
            new byte[]{'E', 'v', 'e', 'c', 'i', 't', 'a', 'S', 'e', 'c', 'r', 'e', 't', 'K', 'e', 'y'};
    private static final byte[] aliceKeyTGS =
            new byte[]{'A', 'l', 'i', 'c', 't', 'g', 's', 'S', 'e', 'c', 'r', 'e', 't', 'K', 'e', 'y'};
    private static final byte[] bobKeyTGS =
            new byte[]{'B', 'o', 'b', 'c', 't', 'g', 's', 'S', 'e', 'c', 'r', 'e', 't', 'K', 'e', 'y'};
    private static final byte[] eveKeyTGS =
            new byte[]{'E', 'v', 'e', 'c', 't', 'g', 's', 'S', 'e', 'c', 'r', 'e', 't', 'K', 'e', 'y'};

    public AS() throws Exception {
        super();
        this.clavesUsuarios = new ArrayList<Key>();
        this.clavesUsuariosTGS = new ArrayList<Key>();
        clavesUsuarios.add(generateKey(aliceKey));
        clavesUsuarios.add(generateKey(bobKey));
        clavesUsuarios.add(generateKey(eveKey));
        clavesUsuariosTGS.add(generateKey(aliceKeyTGS));
        clavesUsuariosTGS.add(generateKey(bobKeyTGS));
        clavesUsuariosTGS.add(generateKey(eveKeyTGS));
        this.aes = new AES();
    }
    
    public int buscarNombre(String nombre){
        for (int i = 0; i < nombres.length; i++) {
            if (nombres[i].equalsIgnoreCase(nombre)) {
                return i;
            }
        }
        return -1;
    }
    
    public String cifrarMensaje(Key clave, String mensaje) throws Exception{
        return this.aes.encrypt(mensaje, clave);
    }
    
    public String obtenerClaveUsuarioTGS(int pos) throws Exception{
         String kUserTgs = Base64.getEncoder().encodeToString(clavesUsuariosTGS.get(pos).getEncoded());
         return cifrarMensaje(this.clavesUsuarios.get(pos), kUserTgs);
    }
 
    public String generarTGT(int pos) throws Exception{ //En el tgt completamente cifrado
//        Calendar cal = Calendar.getInstance();
//        SimpleDateFormat sdf = new SimpleDateFormat("HH:mm:ss");
//        String tiempo = sdf.format(cal.getTime()).toString();
//        cal.get(cal.MINUTE);
        Date inicio = new Date();
        String tiempo = Long.toString(inicio.getTime());

        String kUserTgs = Base64.getEncoder().encodeToString(clavesUsuariosTGS.get(pos).getEncoded());
        String tgt = idUsuarios[pos]+","+ipUsuarios[pos]+","+tiempo+","+kUserTgs;
        
        String cifrado1 = cifrarMensaje(this.ktgs, tgt); //Cifra con la ktgs
        String cifrado2 = cifrarMensaje(this.clavesUsuarios.get(pos), cifrado1); //Cifra el primer cifrado con la clave de usuario
        
        return cifrado2;
    }
    
    private static Key generateKey(byte keyValue []) throws Exception {
        return new SecretKeySpec(keyValue, ALGO);
    }
}
