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
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.Base64;
import java.util.Date;

public class CertificateGenerator {
    private final static String CERTIFICATE_PATH = "src/main/resources/certificates/";

    public static void generateCertificate(CertificateInformation certificateInformation,
                                           String certificatePath) throws Exception {
        Security.addProvider(new BouncyCastleProvider());

        // Generate an RSA key pair
        KeyPair keyPair = CryptoUtil.generateKeyPairRSA();

        X509Certificate certificate =
                createSelfSignedCertificate(keyPair, certificateInformation);

        saveCertificate(certificate, certificatePath);

    }

    public static void saveCertificate(Certificate certificate, String certificateName) throws Exception {
        String certPem = "-----BEGIN CERTIFICATE-----\n" +
                Base64.getEncoder().encodeToString(certificate.getEncoded()) + "\n" +
                "-----END CERTIFICATE-----";

        try (FileOutputStream fos = new FileOutputStream(CERTIFICATE_PATH + certificateName)) {
            fos.write(certPem.getBytes());
        }
    }

    public static X509Certificate createSelfSignedCertificate(KeyPair keyPair,
                                                              CertificateInformation certificateInformation) throws Exception {
        String dirName = new StringBuilder()
                .append("CN=")
                .append(certificateInformation.getCommonName())
                .append(", OU=")
                .append(certificateInformation.getOrganizationalUnit())
                .append(", O=")
                .append(certificateInformation.getOrganization())
                .append(", L=")
                .append(certificateInformation.getLocality())
                .append(", ST=")
                .append(certificateInformation.getState())
                .append(", C=")
                .append(certificateInformation.getState())
                .toString();

        X509v3CertificateBuilder certificateBuilder = getX509v3CertificateBuilder(keyPair, dirName);

        // Create a signer for the certificate
        ContentSigner contentSigner = new JcaContentSignerBuilder("SHA256withRSA")
                .build(keyPair.getPrivate());

        // Sign and create the certificate
        return new JcaX509CertificateConverter()
                .getCertificate(certificateBuilder.build(contentSigner));
    }

    private static X509v3CertificateBuilder getX509v3CertificateBuilder(KeyPair keyPair, String dirName) {
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
        return certificateBuilder;
    }
}
