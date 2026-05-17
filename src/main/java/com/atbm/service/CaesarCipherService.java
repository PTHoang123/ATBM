package com.atbm.service;

import java.security.SecureRandom;

public class CaesarCipherService {
    private static final SecureRandom RANDOM = new SecureRandom();

    public int generateShift(int maxShift) {
        int upperBound = Math.max(2, maxShift);
        return RANDOM.nextInt(upperBound - 1) + 1;
    }

    public String encrypt(String plainText, int shift) {
        return transform(plainText, normalizeShift(shift));
    }

    public String decrypt(String cipherText, int shift) {
        return transform(cipherText, 26 - normalizeShift(shift));
    }

    private String transform(String text, int shift) {
        StringBuilder result = new StringBuilder(text.length());
        for (char ch : text.toCharArray()) {
            if (ch >= 'a' && ch <= 'z') {
                result.append((char) ('a' + (ch - 'a' + shift) % 26));
            } else if (ch >= 'A' && ch <= 'Z') {
                result.append((char) ('A' + (ch - 'A' + shift) % 26));
            } else {
                result.append(ch);
            }
        }
        return result.toString();
    }

    private int normalizeShift(int shift) {
        int normalized = shift % 26;
        return normalized < 0 ? normalized + 26 : normalized;
    }
}
