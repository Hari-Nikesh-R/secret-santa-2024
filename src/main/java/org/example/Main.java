package org.example;

public class Main {
    public static void main(String[] args) {
        String[] clues = {
                "I can chat, code, and create—all at your request.",
                "I'm a digital assistant with knowledge that's vast.",
                "From Java puzzles to creative play, I assist in many a way.",
                "I'm not human but here to help, in bytes and bits where I dwell."
        };

        System.out.println("Can you guess who I am? Here are your clues:\n");

        for (int i = 0; i < clues.length; i++) {
            System.out.println("Clue " + (i + 1) + ": " + clues[i]);
        }

        System.out.println("\nThink you've got it? Type your guess below!");
    }
}
