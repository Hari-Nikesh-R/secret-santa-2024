package org.example;
import java.security.*;
import javax.crypto.Cipher;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.*;

public class Main {
    private static Map<String, String> privateKeys = new HashMap<>();
    private static String encryptedName;
    private static PublicKey publicKey;

    public static void main(String[] args) throws Exception {
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
        keyGen.initialize(2048); // Key size
        KeyPair keyPair = keyGen.generateKeyPair();
        publicKey = keyPair.getPublic();
        PrivateKey privateKey = keyPair.getPrivate();

        String secretName = "HARI NIKESH R";
        encryptedName = encryptWithPublicKey(secretName, publicKey);

        distributePrivateKeys(privateKey);

        System.out.println("Welcome to the Treasure Hunt Game!");
        System.out.println("Rules:");
        System.out.println("1. Solve the riddles to identify the key keepers.");
        System.out.println("2. Collect the private key parts from each keeper.");
        System.out.println("3. Combine the keys in the correct order to decrypt the name.");
        System.out.println("4. Input the combined keys to unlock the secret name.\n");

        playGame();

        Scanner scanner = new Scanner(System.in);
        System.out.print("\nEnter combined private keys in order: ");
        String combinedKeys = scanner.nextLine();

        try {
            String decryptedName = decryptWithPrivateKey(encryptedName, combinedKeys);
            System.out.println("\nCongratulations! You've unlocked the name: " + decryptedName);
        } catch (Exception e) {
            System.out.println("\nIncorrect key combination. Try again!");
        }
        scanner.close();
    }

    private static String encryptWithPublicKey(String data, PublicKey publicKey) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
        byte[] encryptedBytes = cipher.doFinal(data.getBytes());
        return Base64.getEncoder().encodeToString(encryptedBytes);
    }

    private static String decryptWithPrivateKey(String data, String combinedKeys) throws Exception {
        byte[] combinedKeyBytes = Base64.getDecoder().decode(combinedKeys);
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.DECRYPT_MODE, getCombinedPrivateKey(combinedKeyBytes));
        byte[] decryptedBytes = cipher.doFinal(Base64.getDecoder().decode(data));
        return new String(decryptedBytes);
    }

    private static void distributePrivateKeys(PrivateKey privateKey) throws Exception {
        byte[] privateKeyBytes = privateKey.getEncoded();
        int partSize = privateKeyBytes.length / 3; // Split into 3 parts

        privateKeys.put("Keeper1", Base64.getEncoder().encodeToString(Arrays.copyOfRange(privateKeyBytes, 0, partSize)));
        privateKeys.put("Keeper2", Base64.getEncoder().encodeToString(Arrays.copyOfRange(privateKeyBytes, partSize, 2 * partSize)));
        privateKeys.put("Keeper3", Base64.getEncoder().encodeToString(Arrays.copyOfRange(privateKeyBytes, 2 * partSize, privateKeyBytes.length)));
    }

    private static PrivateKey getCombinedPrivateKey(byte[] combinedKeyBytes) throws Exception {
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        return keyFactory.generatePrivate(new PKCS8EncodedKeySpec(combinedKeyBytes));
    }

    private static void playGame() {
        Scanner scanner = new Scanner(System.in);
        String[] riddles = {
                "I am someone who loves numbers and equations. Who am I?", // Keeper1
                "I am known for creativity and artistic flair. Who am I?", // Keeper2
                "I am a tech enthusiast who solves coding puzzles. Who am I?" // Keeper3
        };
        String[] answers = {"Mathematician", "Artist", "Developer"};

        for (int i = 0; i < riddles.length; i++) {
            System.out.println("\nRiddle " + (i + 1) + ": " + riddles[i]);
            System.out.print("Your answer: ");
            String response = scanner.nextLine();

            if (response.equalsIgnoreCase(answers[i])) {
                System.out.println("Correct! You've identified Keeper" + (i + 1));
                System.out.println("Private Key Part: " + privateKeys.get("Keeper" + (i + 1)));
            } else {
                System.out.println("Incorrect! Try again or move to the next riddle.");
            }
        }
    }
}
