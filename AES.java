package org.example.hybrid_key_encryption;
import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.SecureRandom;
import java.util.Base64;

public class AES {

    private static final String AES_TRANSFORMATION = "AES/CBC/PKCS5Padding";
    private static final int IV_SIZE = 16;

    // Generate AES Key
    public static SecretKeySpec generateKey(byte[] keyArray) {
        return new SecretKeySpec(keyArray, "AES");
    }

    // Encrypt
    public static String encrypt(String plaintext, SecretKeySpec key) throws Exception {
        Cipher aes = Cipher.getInstance(AES_TRANSFORMATION);

        byte[] iv = new byte[IV_SIZE];
        SecureRandom random = new SecureRandom();
        random.nextBytes(iv);
        IvParameterSpec ivParams = new IvParameterSpec(iv);

        aes.init(Cipher.ENCRYPT_MODE, key, ivParams);

        byte[] encryptedText = aes.doFinal(plaintext.getBytes());

        byte[] combined = new byte[IV_SIZE + encryptedText.length];
        System.arraycopy(iv, 0, combined, 0, IV_SIZE);
        System.arraycopy(encryptedText, 0, combined, IV_SIZE, encryptedText.length);

        return Base64.getEncoder().encodeToString(combined);
    }

    // Decrypt
    public static String decrypt(String encodedEncryptedText, SecretKeySpec key) throws Exception {
        byte[] combined = Base64.getDecoder().decode(encodedEncryptedText);

        byte[] iv = new byte[IV_SIZE];
        System.arraycopy(combined, 0, iv, 0, IV_SIZE);
        byte[] encryptedText = new byte[combined.length - IV_SIZE];
        System.arraycopy(combined, IV_SIZE, encryptedText, 0, encryptedText.length);

        Cipher aes = Cipher.getInstance(AES_TRANSFORMATION);
        IvParameterSpec ivParams = new IvParameterSpec(iv);

        aes.init(Cipher.DECRYPT_MODE, key, ivParams);

        byte[] decryptedText = aes.doFinal(encryptedText);

        return new String(decryptedText).trim();
    }

}