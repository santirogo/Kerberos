package kerberitos;

import java.util.Date;
import java.util.Scanner;


public class Main {
    public static void main(String[] args) throws Exception {
//        byte[] bobKey =
//            new byte[]{'B', 'o', 'b', 'c', 'i', 't', 'o', 'S', 'e', 'c', 'r', 'e', 't', 'K', 'e', 'y'};
//        
//        Usuarios bob = new Usuarios("bob",bobKey);
        Scanner sc = new Scanner(System.in);
        Date inicio = new Date();
        long tiempo = inicio.getTime();
        
        System.out.println("Digite un número");
        int num = sc.nextInt();
        Date fin = new Date();
        long tiempo2 = fin.getTime();
        long resta = tiempo2 - tiempo;
        resta = resta/(1000*60);
        System.out.println("resta: "+resta);
    }
}
