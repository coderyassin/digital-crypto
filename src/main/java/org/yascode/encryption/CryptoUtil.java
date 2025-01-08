package org.yascode.encryption;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.io.FileInputStream;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import java.util.Base64;

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

    public static KeyPair generateKeyPair(String algorithm) throws Exception {
        KeyPairGenerator keyPairGen = KeyPairGenerator.getInstance(algorithm);
        keyPairGen.initialize(2048);
        return keyPairGen.generateKeyPair();
    }

    public static KeyPair generateKeyPairRSA() throws Exception {
        return generateKeyPair("RSA");
    }

    public static byte[] encrypt(byte[] data, PublicKey publicKey, String algorithm) throws Exception {
        Cipher cipher = Cipher.getInstance(algorithm);
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
        return cipher.doFinal(data);
    }

    public static byte[] encryptRSA(byte[] data, PublicKey publicKey) throws Exception {
        return encrypt(data, publicKey, "RSA");
    }

    public static byte[] decrypt(byte[] encryptedData, PrivateKey privateKey, String algorithm) throws Exception {
        Cipher cipher = Cipher.getInstance(algorithm);
        cipher.init(Cipher.DECRYPT_MODE, privateKey);
        return cipher.doFinal(encryptedData);
    }

    public static byte[] decryptRSA(byte[] encryptedData, PrivateKey privateKey) throws Exception {
        return decrypt(encryptedData, privateKey, "RSA");
    }

    public static PublicKey generatePublicKey(byte[] publicKey, String algorithm) throws Exception {
        return KeyFactory.getInstance(algorithm)
                .generatePublic(new X509EncodedKeySpec(publicKey));
    }

    public static PublicKey generatePublicKeyRSA(byte[] publicKey) throws Exception {
        return generatePublicKey(publicKey, "RSA");
    }

    public static PublicKey generatePublicKeyRSA(String publicKey) throws Exception {
        byte[] decodePublicKey = Base64.getDecoder().decode(publicKey);
        return generatePublicKey(decodePublicKey, "RSA");
    }

    public static PrivateKey generatePrivateKey(byte[] privateKey, String algorithm) throws Exception {
        return KeyFactory.getInstance(algorithm)
                .generatePrivate(new PKCS8EncodedKeySpec(privateKey));
    }

    public static PrivateKey generatePrivateKeyRSA(byte[] privateKey) throws Exception {
        return generatePrivateKey(privateKey, "RSA");
    }

    public static PrivateKey generatePrivateKeyRSA(String privateKey) throws Exception {
        byte[] decodedPrivateKey = Base64.getDecoder().decode(privateKey);
        return generatePrivateKey(decodedPrivateKey, "RSA");
    }

    public static PublicKey publicKeyFromCertificate(String certificatePath) throws Exception {
        CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
        try (FileInputStream fis = new FileInputStream(certificatePath)) {
            Certificate certificate = certificateFactory.generateCertificate(fis);
            return certificate.getPublicKey();
        }
    }

    public static byte[] createDigitalSignature(byte[] data, PrivateKey privateKey) throws Exception {
        Signature signature = Signature.getInstance("SHA256withRSA");
        signature.initSign(privateKey);
        signature.update(data);
        return signature.sign();
    }

    public static boolean verifyDigitalSignature(byte[] data,
                                                 byte[] digitalSignature,
                                                 PublicKey publicKey
                                                 ) throws Exception {
        Signature verification = Signature.getInstance("SHA256withRSA");
        verification.initVerify(publicKey);
        verification.update(data);
        return verification.verify(digitalSignature);
    }

    public static byte[] createHMACSignature(byte[] data, byte[] secretKey) throws Exception {
        SecretKeySpec secretKeySpec = new SecretKeySpec(secretKey, "HmacSHA256");
        Mac mac = Mac.getInstance("HmacSHA256");
        mac.init(secretKeySpec);
        return mac.doFinal(data);
    }

    public static boolean verifyHMACSignature(byte[] data, byte[] signature, byte[] secretKey) throws Exception{
        byte[] hmacSignature = createHMACSignature(data, secretKey);
        return Arrays.equals(hmacSignature, signature);
    }
}
