package kerberitos;

import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.Key;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Calendar;
import java.util.Date;
import javax.crypto.spec.SecretKeySpec;

public class AS extends KDC {

    private AES aes;
    private String idUsuarios[];
    private String ipUsuarios[];
    private ArrayList<Key> clavesUsuarios;
    private ArrayList<Key> clavesUsuariosTGS;
    private static final String ALGO = "AES";
    final int PUERTO = 5000;
    ServerSocket serverSocket;
    Socket socket;

    private static final byte[] aliceKey
            = new byte[]{'A', 'l', 'i', 'c', 'i', 'a', 's', 'S', 'e', 'c', 'r', 'e', 't', 'K', 'e', 'y'};
    private static final byte[] bobKey
            = new byte[]{'B', 'o', 'b', 'c', 'i', 't', 'o', 'S', 'e', 'c', 'r', 'e', 't', 'K', 'e', 'y'};
    private static final byte[] eveKey
            = new byte[]{'E', 'v', 'e', 'c', 'i', 't', 'a', 'S', 'e', 'c', 'r', 'e', 't', 'K', 'e', 'y'};
    private static final byte[] aliceKeyTGS
            = new byte[]{'A', 'l', 'i', 'c', 't', 'g', 's', 'S', 'e', 'c', 'r', 'e', 't', 'K', 'e', 'y'};
    private static final byte[] bobKeyTGS
            = new byte[]{'B', 'o', 'b', 'c', 't', 'g', 's', 'S', 'e', 'c', 'r', 'e', 't', 'K', 'e', 'y'};
    private static final byte[] eveKeyTGS
            = new byte[]{'E', 'v', 'e', 'c', 't', 'g', 's', 'S', 'e', 'c', 'r', 'e', 't', 'K', 'e', 'y'};

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
        idUsuarios = new String[]{"alice","bob","eve"};
        ipUsuarios = new String[]{"ip1","ip2","ip3"};
        this.aes = new AES();
        initServer();
    }

    public void initServer() {

        try {

            serverSocket = new ServerSocket(PUERTO);/* crea socket servidor que escuchara en puerto 5000*/

            socket = new Socket();

            System.out.println("Esperando una conexión:");

            socket = serverSocket.accept();
            //Inicia el socket, ahora esta esperando una conexión por parte del cliente

            System.out.println("Un cliente se ha conectado.");

            //Canales de entrada y salida de datos
            ObjectInputStream ois = new ObjectInputStream(socket.getInputStream());
            ObjectOutputStream oos = new ObjectOutputStream(socket.getOutputStream());

            System.out.println("Confirmando conexion al cliente....");

            //Recepcion id usuario
            
            String idUsuario = (String) ois.readObject();
            int id = buscarNombre(idUsuario);
            
            if(id == -1){
                ois.close();
                oos.close();
                serverSocket.close();
            }else{
                //Envio Clave Sesión
                String claveUsuarioTGS = generarClaveUsuarioTGS(id);
                oos.writeObject(claveUsuarioTGS);
                oos.flush();
                
                //Envio TGT
                String tgt = generarTGT(id);
                oos.writeObject(tgt);
                oos.flush();
            }
            
            System.out.println("Cerrando conexión...");

            ois.close();
            oos.close();
            serverSocket.close();//Aqui se cierra la conexión con el cliente

        } catch (Exception e) {
            System.out.println("Error: " + e.getMessage());
        }
    }

    public int buscarNombre(String nombre) {
        for (int i = 0; i < nombres.length; i++) {
            if (nombres[i].equalsIgnoreCase(nombre)) {
                return i;
            }
        }
        return -1;
    }

    public String cifrarMensaje(Key clave, String mensaje) throws Exception {
        return this.aes.encrypt(mensaje, clave);
    }

    public String generarClaveUsuarioTGS(int pos) throws Exception {
        String kUserTgs = Base64.getEncoder().encodeToString(clavesUsuariosTGS.get(pos).getEncoded());
        return cifrarMensaje(this.clavesUsuarios.get(pos), kUserTgs);
    }

    public String generarTGT(int pos) throws Exception { //En el tgt completamente cifrado
        
        Date inicio = new Date();
        String tiempo = Long.toString(inicio.getTime());
        
        String kUserTgs = Base64.getEncoder().encodeToString(clavesUsuariosTGS.get(pos).getEncoded());
        String tgt = idUsuarios[pos] + "," + ipUsuarios[pos] + "," + tiempo + "," + kUserTgs;
        
        String cifrado1 = cifrarMensaje(this.ktgs, tgt); //Cifra con la ktgs
        String cifrado2 = cifrarMensaje(this.clavesUsuarios.get(pos), cifrado1); //Cifra el primer cifrado con la clave de usuario
        
        return cifrado2;
    }

    private static Key generateKey(byte keyValue[]) throws Exception {
        return new SecretKeySpec(keyValue, ALGO);
    }
}
