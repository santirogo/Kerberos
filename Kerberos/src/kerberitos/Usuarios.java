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
    int PUERTO2 = 5001;
    Socket socket;
    Socket socket2;
    ObjectOutputStream oos;
    ObjectInputStream ois;
    ObjectOutputStream oos2;
    ObjectInputStream ois2;
    String tgt;
    String mensajeAutenticacion;
    Key claveUsuarioTGS;
    
    public Usuarios(String nombre, String servicio, byte clave[]) throws Exception {
        this.nombre = nombre;
        this.servicio = servicio;
        this.claveUsuario = generateKey(clave);
        this.aes = new AES();
        comunicacionConAS();
    }

    public void comunicacionConAS() {
        try {

            socket = new Socket(HOST, PUERTO);
            System.out.println(socket.getInetAddress());
            
            /*conectar a un servidor en localhost con puerto 5000*/

            //creamos el flujo de datos por el que se enviara un mensaje

            oos = new ObjectOutputStream(socket.getOutputStream());
            ois = new ObjectInputStream(socket.getInputStream());
            
            //enviamos el mensaje
            System.out.println("Enviando nombre a AS");
            oos.writeObject(generarNombre());
            
            //Primer mensaje
            System.out.println("");
            System.out.println("Recibiendo mensaje de AS...");
            String primerMensaje = (String) ois.readObject();
            System.out.println("Mesaje recibido: "+primerMensaje);
            String claveUsuarioTGSstr = descifrarMensaje(claveUsuario, primerMensaje);
            System.out.println("Clave Usuario-TGS: "+claveUsuarioTGSstr);
            claveUsuarioTGS = stringToKey(claveUsuarioTGSstr);
            System.out.println("Generando mensaje de autenticion para TGS...");
            mensajeAutenticacion = generarMensajeAutenticacion(claveUsuarioTGS);
            
            //Segundo mensaje
            System.out.println("");
            System.out.println("Recibiendo otro mensaje de AS");
            String segundoMensaje = (String) ois.readObject();
            System.out.println("Segundo mensaje recibido: "+segundoMensaje);
            String tgtDescifrado = descifrarMensaje(claveUsuario, segundoMensaje);
            System.out.println("Mensaje descifrado (Pero aun cifrado con la clave del TGS): "+tgtDescifrado);
            this.tgt = generarMensajeTGT(tgtDescifrado, servicio);
            System.out.println("Generando TGT para TGS...");
            
            //cerramos la conexión
            ois.close();
            oos.close();
            socket.close();
            
            comunicacionConTGS();

        } catch (Exception e) {
            System.out.println("Error: " + e.getMessage());
        }
    }
    
    public void comunicacionConTGS(){
        try {
            
            //Conexion con TGS
            socket2 = new Socket(HOST, PUERTO2);
            oos2 = new ObjectOutputStream(socket2.getOutputStream());
            ois2 = new ObjectInputStream(socket2.getInputStream());
            
            System.out.println("");
            oos2.writeObject(tgt); //Enviamos TGT a TGS
            System.out.println("Enviando TGT a TGS...");
            oos2.writeObject(mensajeAutenticacion); //Enviamos a TGS el client authenticator
            System.out.println("Enviando mensaje de autenticacion a TGS...");
            
            System.out.println("");
            System.out.println("Verificando autenticacion...");
            String verificacionAutenticacion = (String) ois2.readObject();
            System.out.println(verificacionAutenticacion);
            
            if (verificacionAutenticacion.equals("ok")) {
                String verificacionServicio = (String) ois2.readObject();
                if (!verificacionServicio.equalsIgnoreCase("Verificacion correcta")) {
                    System.out.println("Estoy triste porque no puedo hablar con el servidor D':");
                }
                System.out.println(verificacionServicio);
                if (verificacionServicio.equals("Verificacion correcta")) {
                    
                    System.out.println("");
                    System.out.println("Recibiendo mensaje desde TGS...");
                    String sptCifrado = (String) ois2.readObject();
                    System.out.println("SPT cifrado: "+sptCifrado);
                    
                    System.out.println("Recibiendo mensaje desde TGS...");
                    String mensajeSesionCifrado = (String) ois2.readObject();
                    System.out.println("Mensaje de sesion cifrado: "+mensajeSesionCifrado);
                    String mensajeSesionDescifrado = descifrarMensaje(claveUsuarioTGS, mensajeSesionCifrado);
                    System.out.println("Mensaje de sesion descifrado: "+mensajeSesionDescifrado);
                    
                    System.out.println("");
                    System.out.println("La clave con el servidor es: "+mensajeSesionDescifrado);
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

    public void cambiarServicio(String servicio){
        this.servicio = servicio;
        this.PUERTO2 = 5002;
        System.out.println("");
        System.out.println("Cambiando servicio a "+servicio+"...");
        System.out.println("");
        comunicacionConTGS();
    }
    
    private static Key generateKey(byte keyValue[]) throws Exception {
        return new SecretKeySpec(keyValue, ALGO);
    }
}
