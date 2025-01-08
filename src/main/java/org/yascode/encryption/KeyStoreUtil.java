package org.yascode.encryption;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.security.KeyPair;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;

public class KeyStoreUtil {
    private static final String KEY_STORE_PASSWORD = "0112358132134";
    private static final String KEY_STORE_PATH = "src/main/resources/keyStore/";

    public static void buildCertificate(KeyPair keyPair,
                                        String KeystoreName,
                                        String alias,
                                        CertificateInformation certificateInformation) throws Exception {

        X509Certificate certificate = CertificateGenerator.createSelfSignedCertificate(keyPair, certificateInformation);


        savePrivateKey(certificate, keyPair, KeystoreName, alias);
    }

    public static void savePrivateKey(X509Certificate certificate,
                                      KeyPair keyPair,
                                      String KeystoreName,
                                      String alias) throws Exception {
        KeyStore keyStore = KeyStore.getInstance(KeyStore.getDefaultType());
        FileInputStream keyStoreFile = null;

        File keystoreLocation = new File(KEY_STORE_PATH + KeystoreName);
        if (keystoreLocation.exists()) {
            keyStoreFile = new FileInputStream(keystoreLocation);
            keyStore.load(keyStoreFile, KEY_STORE_PASSWORD.toCharArray());
        } else {
            keyStore.load(null, null);  // New keystore, if file does not exist
        }

        KeyStore.PrivateKeyEntry privateKeyEntry =
                new KeyStore.PrivateKeyEntry(keyPair.getPrivate(), new java.security.cert.Certificate[]{certificate});

        keyStore.setEntry(alias, privateKeyEntry, new KeyStore.PasswordProtection(KEY_STORE_PASSWORD.toCharArray()));

        try (FileOutputStream fos = new FileOutputStream(keystoreLocation)) {
            keyStore.store(fos, KEY_STORE_PASSWORD.toCharArray());
        }

        System.out.println("Private key successfully saved to Keystore.");
    }

    public static PrivateKey retrievePrivateKey(String keystore, String alias) throws Exception {
        KeyStore keyStore = loadKeyStore(keystore);
        return  (PrivateKey) keyStore.getKey(alias, KEY_STORE_PASSWORD.toCharArray());
    }

    public static Certificate retrieveCertificate(String keystore, String alias) throws Exception {
        KeyStore keyStore = loadKeyStore(keystore);
        return keyStore.getCertificate(alias);
    }

    private static KeyStore loadKeyStore(String keystore) throws Exception {
        KeyStore keyStore = KeyStore.getInstance(KeyStore.getDefaultType());
        keyStore.load(new FileInputStream(KEY_STORE_PATH + keystore), KEY_STORE_PASSWORD.toCharArray());
        return keyStore;
    }
}
