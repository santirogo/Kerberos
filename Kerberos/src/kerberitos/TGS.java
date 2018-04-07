/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package kerberitos;

import java.security.Key;
import java.util.ArrayList;
import java.util.Base64;
import javax.crypto.interfaces.DHPrivateKey;
import javax.crypto.spec.SecretKeySpec;

public class TGS extends KDC{
    private AES aes;
    private String servicios []; 
    private String permisosUsuario [];
    private static final String ALGO = "AES";
    private ArrayList<Key> clavesUsuariosServidor;
    private Key claveServidor;
    private static final byte[] aliceKey =
            new byte[]{'A', 'l', 'i', 'S', 'e', 'r', 'v', 'S', 'e', 'c', 'r', 'e', 't', 'K', 'e', 'y'};
    private static final byte[] bobKey =
            new byte[]{'B', 'o', 'b', 'S', 'e', 'r', 'v', 'S', 'e', 'c', 'r', 'e', 't', 'K', 'e', 'y'};
    private static final byte[] eveKey =
            new byte[]{'E', 'v', 'e', 'S', 'e', 'r', 'v', 'S', 'e', 'c', 'r', 'e', 't', 'K', 'e', 'y'};
    private static final byte[] serverKey =
            new byte[]{'S', 'p', 'r', 'S', 'e', 'r', 'v', 'S', 'e', 'c', 'r', 'e', 't', 'K', 'e', 'y'};
    
    public TGS() throws Exception {
        super();
        this.aes = new AES();
        this.servicios = new String []{"http","web"}; //Se guarda los servicio disponibles
        this.clavesUsuariosServidor = new ArrayList<Key>();
        this.clavesUsuariosServidor.add(generateKey(aliceKey));
        this.clavesUsuariosServidor.add(generateKey(bobKey));
        this.clavesUsuariosServidor.add(generateKey(eveKey));
        this.claveServidor = generateKey(serverKey);
    }
    
    public String [] separarMensaje(String mensaje){
        String arreglito [] = mensaje.split("!!!");
        return arreglito;
    }
    
    public int verificarServicio(String nombre, String servicio) {

        for (int i = 0; i < servicios.length; i++) {
            if (servicios[i].equalsIgnoreCase(servicio)) {
                for (int j = 0; j < nombres.length; j++) {
                    if (nombres[j].equalsIgnoreCase(nombre)) {
                        if (nombre.equalsIgnoreCase("eve")) {
                            return 1; //El usuario tiene acceso
                        } else if (nombre.equalsIgnoreCase("alice") && servicio.equalsIgnoreCase("http")) {
                            return 1; //El usuario tiene acceso
                        } else if (nombre.equalsIgnoreCase("alice") && servicio.equalsIgnoreCase("web")) {
                            return 0; //El usuario no tiene el permiso para el servicio
                        } else if (nombre.equalsIgnoreCase("bob") && servicio.equalsIgnoreCase("http")) {
                            return 0; //El usuario no tiene el permiso para el servicio
                        } else if (nombre.equalsIgnoreCase("bob") && servicio.equalsIgnoreCase("web")) {
                            return 1; //El usuario tiene acceso
                        }
                    }
                }
                return -2; //si no existe la persona devuelve un -2
            }
        }
        return -1; //si no existe el servicio devuelve un -1
    }
    
    public String [] destriparTGT(String mensaje) throws Exception{
        String descifrado = descifrarMensaje(ktgs, mensaje);
        String arreglito [] = descifrado.split(",");
        return arreglito;
    }
    
    public Key StringToKey(String clave){
        byte[] decodedKey = Base64.getDecoder().decode(clave);
        Key key = new SecretKeySpec(decodedKey, 0, decodedKey.length, ALGO);
        return key;
    }
    
    public String [] obtenerAutenticadorCliente(String mensaje, Key clave) throws Exception{
        return descifrarMensaje(clave, mensaje).split(",");
    }
    
    public String cifrarMensaje(Key clave, String mensaje) throws Exception{
        return this.aes.encrypt(mensaje, clave);
    }
    
    public String descifrarMensaje(Key clave, String mensaje) throws Exception{
        return this.aes.decrypt(mensaje, clave);
    }
    
    public boolean calcularTimeStamp(String tiempo1, String tiempo2){
        long t1 = Long.parseLong(tiempo1);
        long t2 = Long.parseLong(tiempo2);
        
        long resta = t2 - t1;
        resta = resta/(1000*60);
        if (resta < 30) {
            return true;
        }else{
            return false;
        }
        
    }
    
    public int autenticacion(String nombre1, String nombre2, String tiempo1, String tiempo2){
        if(calcularTimeStamp(tiempo1, tiempo2)){
            if (nombre1.equalsIgnoreCase(nombre2)) {
                return 1; //Autenticación correcta
            }else{
                return 0; //id incorrecto
            }
        }else{
            return -1; //Timestamp vencido
        }
        
    }
    
    public String enviarSPT(String id, String ip) throws Exception{
        
        Key claveEnviar = null;
        
        if(id.equalsIgnoreCase("alice")){
            claveEnviar = clavesUsuariosServidor.get(0);
        }else if(id.equalsIgnoreCase("bob")){
            claveEnviar = clavesUsuariosServidor.get(1);
        }else if(id.equalsIgnoreCase("eve")){
            claveEnviar = clavesUsuariosServidor.get(2);
        }
        
        String clave = Base64.getEncoder().encodeToString(claveEnviar.getEncoded());
        
        
        String mensaje = id+","+ip+",60"+clave;
        
        return cifrarMensaje(claveServidor, mensaje);
        
    }
    
    public String generarMensajeSesion(String id, Key clave) throws Exception{
        Key claveEnviar = null;
        
        if(id.equalsIgnoreCase("alice")){
            claveEnviar = clavesUsuariosServidor.get(0);
        }else if(id.equalsIgnoreCase("bob")){
            claveEnviar = clavesUsuariosServidor.get(1);
        }else if(id.equalsIgnoreCase("eve")){
            claveEnviar = clavesUsuariosServidor.get(2);
        }
        
        String clavecita = Base64.getEncoder().encodeToString(claveEnviar.getEncoded());
        
        return cifrarMensaje(clave, clavecita);
    }
    
    private static Key generateKey(byte keyValue []) throws Exception {
        return new SecretKeySpec(keyValue, ALGO);
    }
}
