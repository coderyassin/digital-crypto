package org.yascode;

import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.Pbkdf2PasswordEncoder;
import org.yascode.encryption.CertificateGenerator;
import org.yascode.encryption.CertificateInformation;
import org.yascode.encryption.CryptoUtil;
import org.yascode.encryption.KeyStoreUtil;

import java.security.PrivateKey;
import java.security.SecureRandom;
import java.security.cert.Certificate;
import java.util.Base64;

import static org.springframework.security.crypto.password.Pbkdf2PasswordEncoder.SecretKeyFactoryAlgorithm.PBKDF2WithHmacSHA256;

public class Main {
    private final static String CERTIFICATE_NAME = "certificate.pem";
    private static final String KEYSTORE_NAME = "yasCodeKS.jks";
    private static final String ALIAS = "alias3";
    private static final String COMMON_NAME = "yascode.ja";
    private static final String ORGANIZATIONAL_UNIT = "integration_pro";
    private static final String ORGANIZATION = "yascode";
    private static final String LOCALITY = "casablanca";
    private static final String STATE = "casablanca";
    private static final String COUNTRY = "MR";

    public static void test1(String[] args) throws Exception {
        String data = "This is my data";

        Certificate certificate = KeyStoreUtil.retrieveCertificate(KEYSTORE_NAME, ALIAS);

        CertificateGenerator.saveCertificate(certificate, CERTIFICATE_NAME);

        byte[] encryptedData = CryptoUtil.encryptRSA(data.getBytes(), certificate.getPublicKey());

        PrivateKey privateKey = KeyStoreUtil.retrievePrivateKey(KEYSTORE_NAME, ALIAS);

        byte[] decryptedData = CryptoUtil.decryptRSA(encryptedData, privateKey);

        System.out.println(new String(decryptedData));

    }

    public static void test2(String[] args) throws Exception {
        String data = "This is my data";

        byte[] secretKey = "123456".getBytes();

        byte[] signature = CryptoUtil.createHMACSignature(data.getBytes(), secretKey);

        boolean verifyDigitalSignature = CryptoUtil.verifyHMACSignature(data.getBytes(), signature, secretKey);

        System.out.println(verifyDigitalSignature);
    }

    public static void main(String[] args) throws Exception {
        String password = "123456";
        int strength = 14;
        SecureRandom random1 = SecureRandom.getInstance("SHA1PRNG");
        SecureRandom random2 = SecureRandom.getInstance("Windows-PRNG");

        BCryptPasswordEncoder encoder1 = new BCryptPasswordEncoder(strength, random1);
        BCryptPasswordEncoder encoder2 = new BCryptPasswordEncoder(strength, random2);

        String encodedPassword = encoder1.encode(password);

        System.out.println(encoder2.matches(password, encodedPassword));
    }

    private static CertificateInformation buildCertificateInformation() {
        return new CertificateInformation.Builder()
                .commonName(COMMON_NAME)
                .organizationalUnit(ORGANIZATIONAL_UNIT)
                .organization(ORGANIZATION)
                .locality(LOCALITY)
                .state(STATE)
                .country(COUNTRY)
                .build();
    }

}