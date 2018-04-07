
public class Main {
    public static void main(String[] args) throws Exception {
        byte[] bobKey =
            new byte[]{'B', 'o', 'b', 'c', 'i', 't', 'o', 'S', 'e', 'c', 'r', 'e', 't', 'K', 'e', 'y'};
        
        Usuarios bob = new Usuarios("bob",bobKey);
        
    }
}
