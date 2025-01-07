package org.yascode;

import org.yascode.encryption.CryptoUtil;

import javax.crypto.SecretKey;
import java.util.Base64;

public class Main {
    public static void main(String[] args) throws Exception {
        String data = "This is my data";

        String secret = "SfR4Xl8QIiWxsb00wyHhUIaIXEwcmIPd";

        SecretKey secretKey = CryptoUtil.generateSecretKeyAES(secret);

        byte[] dataEncrypted = CryptoUtil.encryptAES(data.getBytes(), secretKey);

        byte[] decryptedData = CryptoUtil.decryptAES(dataEncrypted, secretKey);

        System.out.println(Base64.getEncoder().encodeToString(dataEncrypted));
        System.out.println(new String(decryptedData));

    }

}