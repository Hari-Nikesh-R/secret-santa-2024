package org.example;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import javax.swing.*;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.nio.file.Files;
import java.nio.file.Paths;
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

public class Main {
    private static final Map<String, String> privateKeys = new HashMap<>();
    private static String encryptedName;
    private static PublicKey publicKey;
    private static JFrame frame;
    private static JTextField keyInputField;
    private static JButton submitButton;
    private static JLabel messageLabel;

    private static void createAndShowGUI() {
        frame = new JFrame("Secret Santa Decryption");
        frame.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
        frame.setSize(400, 200);
        frame.setLocationRelativeTo(null); // Center the frame
        frame.setLayout(new FlowLayout());

        messageLabel = new JLabel("Enter combined private keys:");
        keyInputField = new JTextField(20);  // JTextField for input (20 columns)
        submitButton = new JButton("Submit");
        frame.add(messageLabel);
        frame.add(keyInputField);
        frame.add(submitButton);

        // Action listener for button
        submitButton.addActionListener(new ActionListener() {
            public void actionPerformed(ActionEvent e) {
                String combinedKeys = keyInputField.getText().trim(); // Get text from input field
                try {
                    String decryptedName = decryptWithPrivateKey(encryptedName, combinedKeys);
                    JOptionPane.showMessageDialog(frame, "Congratulations! Your Secret Santa is: " + decryptedName);
                    System.exit(0); // Exit or close after successful decryption
                } catch (Exception ex) {
                    JOptionPane.showMessageDialog(frame, "Incorrect key combination. Try again!", "Error", JOptionPane.ERROR_MESSAGE);
                }
            }
        });

        frame.setVisible(true);
    }


    private static String decrypt(String encryptedText, String secretKey) throws Exception {
        byte[] decodedKey = Base64.getDecoder().decode(secretKey);
        SecretKey originalKey = new SecretKeySpec(decodedKey, 0, decodedKey.length, "AES");

        Cipher cipher = Cipher.getInstance("AES");
        cipher.init(Cipher.DECRYPT_MODE, originalKey);

        byte[] decryptedBytes = cipher.doFinal(Base64.getDecoder().decode(encryptedText));
        return new String(decryptedBytes);
    }

    public static void main(String[] args) throws Exception {
        String privateKeyFilePath = "private_key.txt";
        String publicKeyFilePath = "public_key.txt";
        PrivateKey privateKey;

        if (Files.exists(Paths.get(privateKeyFilePath)) && Files.exists(Paths.get(publicKeyFilePath))) {
            privateKey = KeyUtils.loadPrivateKey(privateKeyFilePath);
            publicKey = KeyUtils.loadPublicKey(publicKeyFilePath);
        } else {
            KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
            keyGen.initialize(2048);
            KeyPair keyPair = keyGen.generateKeyPair();
            privateKey = keyPair.getPrivate();
            publicKey = keyPair.getPublic();
            KeyUtils.saveKeyPair(keyPair, privateKeyFilePath, publicKeyFilePath);
            System.out.println("Keys generated and saved!");
        }


        String secretName = "FTljcUkqyUTVqXz4v0A5qA==";
        String name = decrypt(secretName, "NBr/KBiWFfQnzryvILd0hA==");
        encryptedName = encryptWithPublicKey(name, publicKey);

        distributePrivateKeys(privateKey);

        System.out.println("Welcome to the Treasure Hunt Game!");
        System.out.println("Rules:");
        System.out.println("1. Solve the riddles to identify the key keepers.");
        System.out.println("2. Collect the private key parts from each keeper.");
        System.out.println("3. Combine the keys in the correct order to decrypt the name.");
        System.out.println("4. Input the combined keys to unlock the secret name.\n");
        BufferedReader reader = new BufferedReader(new InputStreamReader(System.in));
        playGame(reader);
        SwingUtilities.invokeLater(Main::createAndShowGUI);
        reader.close();
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

    private static void distributePrivateKeys(PrivateKey privateKey) {
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

    private static void playGame(BufferedReader reader) throws IOException {
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
                    String response = reader.readLine();

                    if (response.equalsIgnoreCase(answers[i]) || response.contains(answers[i])) {
                        System.out.println("Correct! You've identified Keeper" + (i + 1));
                        if (i == (riddles.length - 1)) {
                            ansCount.put(i, true);
                            i = -1;
                        }
                        System.out.println("Collect Private Key from " + ((i == -1) ? answers[riddles.length - 1] : answers[i]));
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
