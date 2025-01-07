package org.yascode;

import org.yascode.encryption.CryptoUtil;

import java.security.KeyPair;

public class Main {
    public static void main(String[] args) throws Exception {
        String data = "This is my data";

        KeyPair keyPair = CryptoUtil.generateKeyPairRSA();

        byte[] encryptedData = CryptoUtil.encryptRSA(data.getBytes(), keyPair.getPublic());

        byte[] decryptedData = CryptoUtil.decryptRSA(encryptedData, keyPair.getPrivate());

        System.out.println(new String(decryptedData));
    }

}