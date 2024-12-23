package org.example;

import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.*;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

public class KeyUtils {
    // Method to save the private and public keys
    public static void saveKeyPair(KeyPair keyPair, String privateKeyFilePath, String publicKeyFilePath) throws Exception {
        // Save private key
        String privateKeyString = Base64.getEncoder().encodeToString(keyPair.getPrivate().getEncoded());
        Files.write(Paths.get(privateKeyFilePath), privateKeyString.getBytes());

        // Save public key
        String publicKeyString = Base64.getEncoder().encodeToString(keyPair.getPublic().getEncoded());
        Files.write(Paths.get(publicKeyFilePath), publicKeyString.getBytes());
    }

    // Method to load the private key
    public static PrivateKey loadPrivateKey(String privateKeyFilePath) throws Exception {
        String privateKeyString = new String(Files.readAllBytes(Paths.get(privateKeyFilePath)));
        byte[] privateKeyBytes = Base64.getDecoder().decode(privateKeyString);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        return keyFactory.generatePrivate(new PKCS8EncodedKeySpec(privateKeyBytes));
    }

    // Method to load the public key
    public static PublicKey loadPublicKey(String publicKeyFilePath) throws Exception {
        String publicKeyString = new String(Files.readAllBytes(Paths.get(publicKeyFilePath)));
        byte[] publicKeyBytes = Base64.getDecoder().decode(publicKeyString);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        return keyFactory.generatePublic(new X509EncodedKeySpec(publicKeyBytes));
    }
}
