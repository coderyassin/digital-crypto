package org.yascode.encryption;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;
import java.util.Formatter;

public class CryptoUtil {
    public static String encodeToBase64(byte[] data){
        return Base64.getEncoder().encodeToString(data);
    }

    public static byte[] decodeFromBase64(String dataBase64){
        return Base64.getDecoder().decode(dataBase64.getBytes());
    }

    public static String encodeToBase64URL(byte[] data){
        return Base64.getUrlEncoder().encodeToString(data);
    }

    public static byte[] decodeFromBase64URL(String dataBase64){
        return Base64.getUrlDecoder().decode(dataBase64.getBytes());
    }

    public static SecretKey generateSecretKey(String algorithm, int keySize) throws NoSuchAlgorithmException {
        KeyGenerator keyGenerator = KeyGenerator.getInstance(algorithm);
        keyGenerator.init(keySize);
        return keyGenerator.generateKey();
    }

    public static SecretKey generateSecretKey(String secret, String algorithm) throws Exception{
        SecretKey secretKey = new SecretKeySpec(secret.getBytes(),0, secret.length(), algorithm);
        return secretKey;
    }

    public static SecretKey generateSecretKeyAES(int keySize) throws NoSuchAlgorithmException {
        return generateSecretKey("AES", keySize);
    }

    public static SecretKey generateSecretKeyAES(String secret) throws Exception{
        return generateSecretKey(secret, "AES");
    }

    public static byte[] encrypt(byte[] data, SecretKey secretKey, String algorithm) throws Exception {
        Cipher cipher = Cipher.getInstance(algorithm);
        cipher.init(Cipher.ENCRYPT_MODE, secretKey);
        return cipher.doFinal(data);
    }

    public static byte[] decrypt(byte[] encryptedData, SecretKey secretKey, String algorithm) throws Exception {
        Cipher cipher = Cipher.getInstance(algorithm);
        cipher.init(Cipher.DECRYPT_MODE, secretKey);
        return cipher.doFinal(encryptedData);
    }

    public static byte[] encryptAES(byte[] data, SecretKey secretKey) throws Exception {
        return encrypt(data, secretKey, "AES");
    }

    public static byte[] decryptAES(byte[] encryptedData, SecretKey secretKey) throws Exception {
        return decrypt(encryptedData, secretKey, "AES");
    }
}
