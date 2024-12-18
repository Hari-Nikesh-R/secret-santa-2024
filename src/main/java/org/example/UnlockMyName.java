package org.example;

import java.util.HashMap;
import java.util.Random;
import java.util.Scanner;
import java.util.random.RandomGenerator;

public class UnlockMyName {
    // Simulated key storage
    private static HashMap<String, String> keys = new HashMap<>();
    private static String secretName = "HARI NIKESH R"; // Replace with your name
    private static String encryptedName = encryptName(secretName);
    private static int randomNumber = (int)(Math.random() * 50 + 1);


    public static void main(String[] args) {
        distributeKeys();

        System.out.println("Welcome to 'Unlock My Name'!");
        System.out.println("The goal is to combine all the keys to reveal the hidden name.");


        System.out.println("\nRules:");
        System.out.println("1. Each account has a clue about the person.");
        System.out.println("2. Combine all the keys from the accounts to decrypt the hidden name.");
        System.out.println("3. Use the keys in the correct order!");

        for (String account : keys.keySet()) {
            System.out.println("\nAccount: " + account);
            System.out.println("Clue: " + getClue(account));
            System.out.println("Key: " + keys.get(account));
        }

        System.out.println("\nCan you figure out the name? Enter the combined keys in order:");


        Scanner scanner = new Scanner(System.in);
        System.out.print("Enter combined keys: ");
        String combinedKeys = scanner.nextLine();


        String decryptedName = decryptName(combinedKeys);
        if (decryptedName.equals(secretName)) {
            System.out.println("Congratulations! You've unlocked the name: " + decryptedName);
        } else {
            System.out.println("Oops! That's not correct. Try again.");
        }

        scanner.close();
    }


    private static void distributeKeys() {
        keys.put("Account1", encryptedName.substring(0, 2)); // First 2 characters
        keys.put("Account2", encryptedName.substring(2, 4)); // Next 2 characters
        keys.put("Account3", encryptedName.substring(4));    // Last characters
    }

    private static String getClue(String account) {
        switch (account) {
            case "Account1":
                return "I'm knowledgeable and love to assist with code.";
            case "Account2":
                return "I respond instantly and can chat about anything.";
            case "Account3":
                return "People rely on me to solve problems and learn.";
            default:
                return "No clue available.";
        }
    }


    private static String encryptName(String name) {
        StringBuilder encrypted = new StringBuilder();
        for (char c : name.toCharArray()) {
            encrypted.append((char) (c + randomNumber));
        }
        return encrypted.toString();
    }


    private static String decryptName(String encrypted) {
        StringBuilder decrypted = new StringBuilder();
        for (char c : encrypted.toCharArray()) {
            decrypted.append((char) (c - randomNumber));
        }
        return decrypted.toString();
    }
}
