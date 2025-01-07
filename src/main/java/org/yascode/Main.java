package org.yascode;

import org.yascode.encryption.CryptoUtil;
import org.yascode.encryption.KeyStoreUtil;

import java.security.KeyPair;
import java.security.PrivateKey;

public class Main {
    private static final String KEYSTORE_NAME = "yasCodeKS.jks";
    private static final String ALIAS = "alias2";
    private static final String COMMON_NAME = "yascode.j";
    private static final String ORGANIZATIONAL_UNIT = "integration";
    private static final String ORGANIZATION = "yascode";
    private static final String LOCALITY = "casablanca";
    private static final String STATE = "casablanca";
    private static final String COUNTRY = "MR";

    public static void main(String[] args) throws Exception {
        String data = "This is my data";

        KeyPair keyPair = CryptoUtil.generateKeyPairRSA();

        PrivateKey privateKey = KeyStoreUtil.retrievePrivateKey(KEYSTORE_NAME, ALIAS);

        KeyStoreUtil.savePrivateKey(keyPair,
                KEYSTORE_NAME,
                ALIAS,
                COMMON_NAME,
                ORGANIZATIONAL_UNIT,
                ORGANIZATION,
                LOCALITY,
                STATE,
                COUNTRY);

    }

}