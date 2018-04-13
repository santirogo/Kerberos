package kerberitos;

import java.util.Date;
import java.util.Scanner;


public class Main1 {
    public static void main(String[] args) throws Exception {
        
        byte[] aliceKey =
            new byte[]{'A', 'l', 'i', 'c', 'i', 'a', 's', 'S', 'e', 'c', 'r', 'e', 't', 'K', 'e', 'y'};
        
        byte[] bobKey =
            new byte[]{'B', 'o', 'b', 'c', 'i', 't', 'o', 'S', 'e', 'c', 'r', 'e', 't', 'K', 'e', 'y'};
        
        Usuarios alice = new Usuarios("alice","http",aliceKey);
    }
}
