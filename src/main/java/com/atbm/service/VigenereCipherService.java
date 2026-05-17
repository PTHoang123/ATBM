package com.atbm.service;

import java.security.SecureRandom;

public class VigenereCipherService {
    private static final SecureRandom RANDOM = new SecureRandom();

    public String generateKey(int length) {
        int safeLength = Math.max(1, length);
        StringBuilder key = new StringBuilder(safeLength);
        for (int index = 0; index < safeLength; index++) {
            key.append((char) ('A' + RANDOM.nextInt(26)));
        }
        return key.toString();
    }

    public String encrypt(String plainText, String key) {
        return transform(plainText, normalizeKey(key), true);
    }

    public String decrypt(String cipherText, String key) {
        return transform(cipherText, normalizeKey(key), false);
    }

    private String transform(String input, String key, boolean encrypt) {
        if (key.isEmpty()) {
            throw new IllegalArgumentException("Key Vigenere không được để trống.");
        }

        StringBuilder output = new StringBuilder(input.length());
        int keyIndex = 0;

        for (char ch : input.toCharArray()) {
            if (Character.isLetter(ch)) {
                char keyChar = key.charAt(keyIndex % key.length());
                int keyShift = keyChar - 'A';
                int base = Character.isLowerCase(ch) ? 'a' : 'A';
                int plainIndex = Character.toUpperCase(ch) - 'A';
                int cipherIndex = encrypt
                        ? (plainIndex + keyShift) % 26
                        : (plainIndex - keyShift + 26) % 26;
                output.append((char) (base + cipherIndex));
                keyIndex++;
            } else {
                output.append(ch);
            }
        }

        return output.toString();
    }

    private String normalizeKey(String key) {
        if (key == null) {
            return "";
        }

        return key.replaceAll("[^A-Za-z]", "").toUpperCase().trim();
    }
}