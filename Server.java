package org.example.hybrid_key_encryption;
import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Base64;
import java.util.Scanner;

public class Server {
    static  int PORT = 9999;

    // Generate RSA key pair
    private static KeyPair generateRSAKeyPair() throws Exception {
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
        keyGen.initialize(2048);
        return keyGen.generateKeyPair();
    }

    // Decrypt AES key
    private static SecretKey decryptAESKey(String encryptedAESKey, PrivateKey privateKey) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.DECRYPT_MODE, privateKey);
        byte[] decodedKey = Base64.getDecoder().decode(encryptedAESKey);
        byte[] decryptedKey = cipher.doFinal(decodedKey);
        return new SecretKeySpec(decryptedKey, 0, decryptedKey.length, "AES");
    }

    public static void main(String[] args) throws Exception {
        System.out.println("========= Server Side =========");

        ServerSocket server_socket = new ServerSocket(PORT);

        KeyPair rsaKeyPair = generateRSAKeyPair();
        PublicKey publicKey = rsaKeyPair.getPublic();
        PrivateKey privateKey = rsaKeyPair.getPrivate();

        try {
            while (true) {
                Socket socket = server_socket.accept();
                System.out.println("A client connected....");

                ObjectOutputStream outputStream = new ObjectOutputStream(socket.getOutputStream());
                ObjectInputStream inputStream = new ObjectInputStream(socket.getInputStream());

                // Send RSA Public Key
                String encodedPublicKey = Base64.getEncoder().encodeToString(publicKey.getEncoded());
                outputStream.writeObject(encodedPublicKey);
                System.out.println("Public key sent to client!");

                // Receive Encrypted AES
                String encryptedAESKey = (String) inputStream.readObject();
                System.out.println("Received encrypted AES key from client!");

                // Decrypt AES Key with RSA Private Key
                SecretKey aesKey = decryptAESKey(encryptedAESKey, privateKey);
                System.out.println("Decrypted AES Key: " + Base64.getEncoder().encodeToString(aesKey.getEncoded()));
                System.out.println("---------------------------------------------------------------------------------------");

                // chat application
                try {
                    PrintWriter out = new PrintWriter((socket.getOutputStream()), true);
                    out.println("welcome to chat application.....");
                    BufferedReader in = new BufferedReader(new InputStreamReader(socket.getInputStream()));
                    Scanner scan = new Scanner(System.in);

                    while(true){
                        String msg = in.readLine();
                        System.out.println("client says : " + msg);

                        // Decrypting the recieving message with AES key
                        String decryptedText = AES.decrypt(msg, (SecretKeySpec) aesKey);
                        System.out.println("Decrypted message : " + decryptedText);
                        System.out.println("---------------------------------------------------------------------------------------");

                        String chat = scan.nextLine();

                        // Encrypting the sending message with AES key
                        String encryptedText = AES.encrypt(chat, (SecretKeySpec) aesKey);
                        System.out.println("Encrypted message : " + encryptedText);
                        System.out.println("---------------------------------------------------------------------------------------");
                        PrintWriter out1 = new PrintWriter((socket.getOutputStream()), true);
                        out1.println(encryptedText);


                    }
                }finally {
                    socket.close();
                }
            }
        } finally {
            server_socket.close();
        }
    }


}