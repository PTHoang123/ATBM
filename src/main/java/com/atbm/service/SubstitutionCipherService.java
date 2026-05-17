package com.atbm.service;

import java.security.SecureRandom;

public class SubstitutionCipherService {
    private static final String ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
    private static final SecureRandom RANDOM = new SecureRandom();

    public String generateKey() {
        char[] characters = ALPHABET.toCharArray();
        for (int index = characters.length - 1; index > 0; index--) {
            int swapIndex = RANDOM.nextInt(index + 1);
            char temporary = characters[index];
            characters[index] = characters[swapIndex];
            characters[swapIndex] = temporary;
        }
        return new String(characters);
    }

    public String encrypt(String plainText, String key) {
        String normalizedKey = normalizeKey(key);
        validateKey(normalizedKey);
        return transform(plainText, ALPHABET, normalizedKey);
    }

    public String decrypt(String cipherText, String key) {
        String normalizedKey = normalizeKey(key);
        validateKey(normalizedKey);
        return transform(cipherText, normalizedKey, ALPHABET);
    }

    private String transform(String input, String sourceAlphabet, String targetAlphabet) {
        StringBuilder output = new StringBuilder(input.length());
        for (char ch : input.toCharArray()) {
            int index = sourceAlphabet.indexOf(Character.toUpperCase(ch));
            if (index >= 0) {
                char mapped = targetAlphabet.charAt(index);
                output.append(Character.isLowerCase(ch) ? Character.toLowerCase(mapped) : mapped);
            } else {
                output.append(ch);
            }
        }
        return output.toString();
    }

    private String normalizeKey(String key) {
        return key == null ? "" : key.trim().toUpperCase();
    }

    private void validateKey(String key) {
        if (key.length() != 26) {
            throw new IllegalArgumentException("Key thay thế phải có đúng 26 ký tự.");
        }

        boolean[] seen = new boolean[26];
        for (char ch : key.toCharArray()) {
            if (ch < 'A' || ch > 'Z') {
                throw new IllegalArgumentException("Key thay thế chỉ được chứa chữ cái A-Z.");
            }

            int index = ch - 'A';
            if (seen[index]) {
                throw new IllegalArgumentException("Key thay thế không được lặp ký tự.");
            }
            seen[index] = true;
        }
    }
}