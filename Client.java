package org.example.hybrid_key_encryption;
import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.net.InetAddress;
import java.net.Socket;
import java.net.UnknownHostException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.Scanner;

public class Client {
    static int PORT = 9999;

    // Encrypt AES key
    private static String encryptAESKey(SecretKey aesKey, PublicKey publicKey) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
        byte[] encryptedKey = cipher.doFinal(aesKey.getEncoded());
        return Base64.getEncoder().encodeToString(encryptedKey);
    }

    public static void main(String[] args) throws Exception {
        System.out.println("===== client side ======");

        InetAddress ip_address = InetAddress.getLocalHost();

        Socket socket = new Socket(ip_address, PORT);

        System.out.println("server connected .....");

        ObjectOutputStream outputStream = new ObjectOutputStream(socket.getOutputStream());
        ObjectInputStream inputStream = new ObjectInputStream(socket.getInputStream());

        // Receive RSA Public Key
        String encodedPublicKey = (String) inputStream.readObject();
        byte[] decodedPublicKey = Base64.getDecoder().decode(encodedPublicKey);
        PublicKey publicKey = KeyFactory.getInstance("RSA").generatePublic(new X509EncodedKeySpec(decodedPublicKey));

        // Generate AES key
        SecretKey aesKey;
        byte[] key_array =new byte[] {'T','h','e','B','e','s','t','K','e','y', '1', '2', '3', '4','5','6'};
        aesKey = AES.generateKey(key_array);
        try {

            System.out.println("Generated AES Key: " + Base64.getEncoder().encodeToString(aesKey.getEncoded()));

            // Encrypt AES key with RSA public key
            String encryptedAESKey = encryptAESKey(aesKey, publicKey);
            System.out.println("Encrypted AES Key: " + encryptedAESKey);

            // Send the encrypted AES key
            outputStream.writeObject(encryptedAESKey);
            outputStream.flush();
            System.out.println("Encrypted AES key sent to server!");
        } catch (Exception e) {
            e.printStackTrace();
        }

        BufferedReader in = new BufferedReader(new InputStreamReader(socket.getInputStream()));

        Scanner scan = new Scanner(System.in);

        // Chat Application
        while(true){
            String msg = in.readLine();
            System.out.println("server says : " + msg);
            if (msg.startsWith("welcome") || Base64.getDecoder().decode(msg).equals(null)) {
                System.out.println(" ");
            } else {
                // Decrypting the recieving message with AES key
                try {
                    String decryptedText = AES.decrypt(msg, (SecretKeySpec) aesKey);
                    System.out.println("Decrypted message : " + decryptedText);
                } catch (IllegalArgumentException e) {
                    System.out.println("Invalid Base64 or decryption error: " + e.getMessage());
                }
            }
            System.out.println("---------------------------------------------------------------------------------------");
            String chat = scan.nextLine();

            // Encrypting the sending message with AES key
            String encryptedText = AES.encrypt(chat, (SecretKeySpec) aesKey);
            System.out.println("Encrypted message : " + encryptedText);
            System.out.println("---------------------------------------------------------------------------------------");
            if (chat == "q"){
                break;
            }
            PrintWriter out = new PrintWriter((socket.getOutputStream()), true);
            out.println(encryptedText);

        }

        socket.close();
        in.close();
    }

}