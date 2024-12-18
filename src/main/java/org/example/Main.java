package org.example;

import javax.crypto.Cipher;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Arrays;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;
import java.util.Scanner;

public class Main {
    private static final Map<String, String> privateKeys = new HashMap<>();
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
        while (true) {

            System.out.print("\nEnter combined private keys in order: ");
            String combinedKeys = scanner.nextLine();

            try {
                String decryptedName = decryptWithPrivateKey(encryptedName, combinedKeys);
                System.out.println("\nCongratulations! You're Secret Santa is : " + decryptedName);
                break;
            } catch (Exception e) {
                System.out.println("\nIncorrect key combination. Try again!");
            }

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
        int partSize = privateKeyBytes.length / 3;

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
                "I'm senior than you. I'm part of your team. I love sports and I'm friendly. Who am I?",
                "We talk occasionally. I switched 3 teams within our org. One of your friends (Monisha, Dharshini, JeevaDharshini)[anyone] already worked with me. Who am I?",
                "I love to motivate people and organize things. I'm senior than you, I sit alone. Who am I?"
        };
        String[] answers = {"Ashok Kumar", "Hari Nikesh", "Sujitha"};
        Map<Integer, Boolean> ansCount = new HashMap<>();
        while (true) {
            for (int i = 0; i < riddles.length; i++) {
                if (Boolean.FALSE.equals(ansCount.getOrDefault(i, false))) {
                    System.out.println("\nRiddle " + (i + 1) + ": " + riddles[i]);
                    System.out.print("Your answer: ");
                    String response = scanner.nextLine();

                    if (response.equalsIgnoreCase(answers[i]) || response.contains(answers[i])) {
                        System.out.println("Correct! You've identified Keeper" + (i + 1));
                        if (i == (riddles.length - 1)) {
                            ansCount.put(i, true);
                            i = -1;
                        }
                       System.out.println("Private Key Part: " + privateKeys.get("Keeper" + ((i + 1) + 1)));
//                        System.out.println("Collect Private Key from " + ((i == -1) ? answers[riddles.length - 1] : answers[i]));
                        if (i >= 0) {
                            ansCount.put(i, true);
                        }
                    } else {
                        System.out.println("Incorrect! Try again or move to the next riddle.");
                        ansCount.put(i, false);
                    }
                }

            }
            if (calculateAns(ansCount)) {
                break;
            }
        }
    }

    static boolean calculateAns(Map<Integer, Boolean> ansCount) {
        return ansCount.values().stream().allMatch(Boolean::booleanValue);
    }
}
