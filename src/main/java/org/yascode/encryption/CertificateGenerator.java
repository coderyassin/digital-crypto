package org.yascode.encryption;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

import java.io.FileOutputStream;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.SecureRandom;
import java.security.Security;
import java.security.cert.X509Certificate;
import java.util.Base64;
import java.util.Date;

public class CertificateGenerator {

    public static void generateCertificate(String commonName,
                                           String organizationalUnit,
                                           String organization,
                                           String locality,
                                           String state,
                                           String country) throws Exception {
        Security.addProvider(new BouncyCastleProvider());

        // Generate an RSA key pair
        KeyPair keyPair = CryptoUtil.generateKeyPairRSA();

        X509Certificate certificate =
                createSelfSignedCertificate(keyPair, commonName, organizationalUnit, organization, locality, state, country);

        // Save the certificate as PEM
        String certPem = "-----BEGIN CERTIFICATE-----\n" +
                Base64.getEncoder().encodeToString(certificate.getEncoded()) + "\n" +
                "-----END CERTIFICATE-----";

        String certificatePath = "src/main/resources/certificates/certificate.pem";
        try (FileOutputStream fos = new FileOutputStream(certificatePath)) {
            fos.write(certPem.getBytes());
        }

    }

    public static X509Certificate createSelfSignedCertificate(KeyPair keyPair,
                                                              String commonName,
                                                              String organizationalUnit,
                                                              String organization,
                                                              String locality,
                                                              String state,
                                                              String country) throws Exception {
        String dirName = new StringBuilder()
                .append("CN=")
                .append(commonName)
                .append(", OU=")
                .append(organizationalUnit)
                .append(", O=")
                .append(organization)
                .append(", L=")
                .append(locality)
                .append(", ST=")
                .append(state)
                .append(", C=")
                .append(country)
                .toString();

        X500Name subjectName = new X500Name(dirName);
        BigInteger serialNumber = new BigInteger(64, new SecureRandom());
        Date startDate = new Date();
        Date endDate = new Date(startDate.getTime() + 365L * 24 * 60 * 60 * 1000); // certificate valid for 1 year

        // Construire le certificat X509v3
        X509v3CertificateBuilder certificateBuilder = new JcaX509v3CertificateBuilder(
                subjectName,
                serialNumber,
                startDate,
                endDate,
                subjectName, // the certificate is self-signed, so the issuer name is the same as the subject name
                keyPair.getPublic()
        );

        // Create a signer for the certificate
        ContentSigner contentSigner = new JcaContentSignerBuilder("SHA256withRSA")
                //.setProvider("BC")
                .build(keyPair.getPrivate());

        // Sign and create the certificate
        return new JcaX509CertificateConverter()
                //.setProvider("BC")
                .getCertificate(certificateBuilder.build(contentSigner));
    }
}
