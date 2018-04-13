package kerberitos;

import java.util.Date;
import java.util.Scanner;


public class Main1 {
    public static void main(String[] args) throws Exception {
        
        byte[] aliceKey =
            new byte[]{'A', 'l', 'i', 'c', 'i', 'a', 's', 'S', 'e', 'c', 'r', 'e', 't', 'K', 'e', 'y'};
        
        byte[] bobKey =
            new byte[]{'B', 'o', 'b', 'c', 'i', 't', 'o', 'S', 'e', 'c', 'r', 'e', 't', 'K', 'e', 'y'};
        
        byte[] eveKey =
            new byte[]{'E', 'v', 'e', 'c', 'i', 't', 'a', 'S', 'e', 'c', 'r', 'e', 't', 'K', 'e', 'y'};
        
//        Usuarios alice = new Usuarios("alice","http",aliceKey);
//        Usuarios bob = new Usuarios("bob", "web", bobKey);
        Usuarios eve = new Usuarios("eve", "web", eveKey);
        eve.cambiarServicio("http");
    }
}
