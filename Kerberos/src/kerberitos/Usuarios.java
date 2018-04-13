package kerberitos;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.net.Socket;
import java.security.Key;
import java.text.SimpleDateFormat;
import java.util.Base64;
import java.util.Calendar;
import java.util.Date;
import javax.crypto.spec.SecretKeySpec;

public class Usuarios {

    private String nombre;
    private String servicio;
    private Key claveUsuario;
    private AES aes;
    private static final String ALGO = "AES";
    final String HOST = "localhost";
    final int PUERTO = 5000;
    final int PUERTO2 = 5001;
    Socket socket;
    Socket socket2;
    ObjectOutputStream oos;
    ObjectInputStream ois;
    ObjectOutputStream oos2;
    ObjectInputStream ois2;
    
    public Usuarios(String nombre, String servicio, byte clave[]) throws Exception {
        this.nombre = nombre;
        this.servicio = servicio;
        this.claveUsuario = generateKey(clave);
        this.aes = new AES();
        initClient();
    }

    public void initClient() {
        try {

            socket = new Socket(HOST, PUERTO);
            
            /*conectar a un servidor en localhost con puerto 5000*/

            //creamos el flujo de datos por el que se enviara un mensaje

            oos = new ObjectOutputStream(socket.getOutputStream());
            ois = new ObjectInputStream(socket.getInputStream());
            
            //enviamos el mensaje
            oos.writeObject(generarNombre());
            
            //Primer mensaje
            String primerMensaje = (String) ois.readObject();
            String claveUsuarioTGSstr = descifrarMensaje(claveUsuario, primerMensaje);
            Key claveUsuarioTGS = stringToKey(claveUsuarioTGSstr);
            String mensajeAutenticacion = generarMensajeAutenticacion(claveUsuarioTGS);
            
            //Segundo mensaje
            String segundoMensaje = (String) ois.readObject();
            String tgtDescifrado = descifrarMensaje(claveUsuario, segundoMensaje);
            String tgt = generarMensajeTGT(tgtDescifrado, servicio);
            
            //cerramos la conexión
            ois.close();
            oos.close();
            socket.close();
            
            //Conexion con TGS
            socket2 = new Socket(HOST, PUERTO2);
            oos2 = new ObjectOutputStream(socket2.getOutputStream());
            ois2 = new ObjectInputStream(socket2.getInputStream());

            oos2.writeObject(tgt); //Enviamos TGT a TGS
            oos2.writeObject(mensajeAutenticacion); //Enviamos a TGS el client authenticator
            
            String verificacionAutenticacion = (String) ois2.readObject();
            System.out.println(verificacionAutenticacion);
            
            if (verificacionAutenticacion.equals("ok")) {
                String verificacionServicio = (String) ois2.readObject();
                System.out.println(verificacionServicio);
                if (verificacionServicio.equals("Verificacion correcta")) {
                    String sptCifrado = (String) ois2.readObject();
                    
                    String mensajeSesionCifrado = (String) ois2.readObject();
                    String mensajeSesionDescifrado = descifrarMensaje(claveUsuarioTGS, mensajeSesionCifrado);
                    System.out.println("La clave con el servido es: "+mensajeSesionDescifrado);
                    System.out.println("Estoy feliz porque puedo hablar con el servidor :D");
                }
            }
            
            //cerramos la conexión
            ois2.close();
            oos2.close();
            socket2.close();

        } catch (Exception e) {
            System.out.println("Error: " + e.getMessage());
        }
    }

    public String cifrarMensaje(Key clave, String mensaje) throws Exception {
        return this.aes.encrypt(mensaje, clave);
    }

    public String descifrarMensaje(Key clave, String mensaje) throws Exception {
        return this.aes.decrypt(mensaje, clave);
    }
    
    public Key stringToKey(String clave){
        byte[] decodedKey = Base64.getDecoder().decode(clave);
        Key key = new SecretKeySpec(decodedKey, 0, decodedKey.length, ALGO);
        return key;
    }
    
    public String generarNombre(){
        return this.nombre;
    }

    public String generarMensajeAutenticacion(Key clave) throws Exception {
        Date tiempo = new Date();
        String envio = Long.toString(tiempo.getTime());

        String mensaje = nombre + "," + envio;
        return cifrarMensaje(clave, mensaje);
    }

    public String generarMensajeTGT(String tgt, String servicio) {
        return tgt + "!!!" + servicio;
    }

    private static Key generateKey(byte keyValue[]) throws Exception {
        return new SecretKeySpec(keyValue, ALGO);
    }
}
