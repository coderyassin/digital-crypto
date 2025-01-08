package org.yascode;

import org.yascode.encryption.CertificateGenerator;
import org.yascode.encryption.CertificateInformation;
import org.yascode.encryption.CryptoUtil;
import org.yascode.encryption.KeyStoreUtil;

import java.security.PrivateKey;
import java.security.cert.Certificate;

public class Main {
    private static final String KEYSTORE_NAME = "yasCodeKS.jks";
    private static final String ALIAS = "alias3";
    private static final String COMMON_NAME = "yascode.ja";
    private static final String ORGANIZATIONAL_UNIT = "integration_pro";
    private static final String ORGANIZATION = "yascode";
    private static final String LOCALITY = "casablanca";
    private static final String STATE = "casablanca";
    private static final String COUNTRY = "MR";

    public static void main(String[] args) throws Exception {
        String data = "This is my data";

        Certificate certificate = KeyStoreUtil.retrieveCertificate(KEYSTORE_NAME, ALIAS);

        CertificateGenerator.saveCertificate(certificate, "src/main/resources/certificates/certificate.pem");

        byte[] encryptedData = CryptoUtil.encryptRSA(data.getBytes(), certificate.getPublicKey());

        PrivateKey privateKey = KeyStoreUtil.retrievePrivateKey(KEYSTORE_NAME, ALIAS);

        byte[] decryptedData = CryptoUtil.decryptRSA(encryptedData, privateKey);

        System.out.println(new String(decryptedData));

    }

    private static CertificateInformation getCertificateInformation() {
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