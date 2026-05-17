package com.atbm.service;

import java.security.SecureRandom;

public class HillCipherService {
    private static final SecureRandom RANDOM = new SecureRandom();
    private static final int MOD = 26;

    public String generateKey() {
        while (true) {
            int a = RANDOM.nextInt(MOD);
            int b = RANDOM.nextInt(MOD);
            int c = RANDOM.nextInt(MOD);
            int d = RANDOM.nextInt(MOD);
            int determinant = normalize(a * d - b * c);
            if (gcd(determinant, MOD) == 1) {
                return a + "," + b + "," + c + "," + d;
            }
        }
    }

    public String encrypt(String plainText, String key) {
        int[] matrix = parseKey(key);
        String letters = extractLetters(plainText);
        if (letters.length() % 2 != 0) {
            letters += 'X';
        }

        StringBuilder output = new StringBuilder(letters.length());
        for (int index = 0; index < letters.length(); index += 2) {
            int first = letters.charAt(index) - 'A';
            int second = letters.charAt(index + 1) - 'A';
            int encryptedFirst = normalize(matrix[0] * first + matrix[1] * second);
            int encryptedSecond = normalize(matrix[2] * first + matrix[3] * second);
            output.append((char) ('A' + encryptedFirst));
            output.append((char) ('A' + encryptedSecond));
        }

        return output.toString();
    }

    public String decrypt(String cipherText, String key) {
        int[] matrix = parseKey(key);
        int determinant = normalize(matrix[0] * matrix[3] - matrix[1] * matrix[2]);
        int inverseDeterminant = modularInverse(determinant);
        int[] inverseMatrix = new int[]{
                normalize(matrix[3] * inverseDeterminant),
                normalize(-matrix[1] * inverseDeterminant),
                normalize(-matrix[2] * inverseDeterminant),
                normalize(matrix[0] * inverseDeterminant)
        };

        String letters = extractLetters(cipherText);
        if (letters.length() % 2 != 0) {
            letters += 'X';
        }

        StringBuilder output = new StringBuilder(letters.length());
        for (int index = 0; index < letters.length(); index += 2) {
            int first = letters.charAt(index) - 'A';
            int second = letters.charAt(index + 1) - 'A';
            int plainFirst = normalize(inverseMatrix[0] * first + inverseMatrix[1] * second);
            int plainSecond = normalize(inverseMatrix[2] * first + inverseMatrix[3] * second);
            output.append((char) ('A' + plainFirst));
            output.append((char) ('A' + plainSecond));
        }

        return output.toString();
    }

    private String extractLetters(String text) {
        StringBuilder letters = new StringBuilder();
        for (char ch : text.toCharArray()) {
            if (Character.isLetter(ch)) {
                letters.append(Character.toUpperCase(ch));
            }
        }
        return letters.toString();
    }

    private int[] parseKey(String key) {
        if (key == null || key.trim().isEmpty()) {
            throw new IllegalArgumentException("Vui lòng nhập key Hill dạng a,b,c,d hoặc bật tự tạo key.");
        }

        String[] parts = key.trim().split("[,;:\\s]+");
        if (parts.length != 4) {
            throw new IllegalArgumentException("Key Hill phải có đúng 4 số, ví dụ 3,3,2,5");
        }

        try {
            int a = normalize(Integer.parseInt(parts[0]));
            int b = normalize(Integer.parseInt(parts[1]));
            int c = normalize(Integer.parseInt(parts[2]));
            int d = normalize(Integer.parseInt(parts[3]));
            int determinant = normalize(a * d - b * c);
            if (gcd(determinant, MOD) != 1) {
                throw new IllegalArgumentException("Ma trận Hill không khả nghịch mod 26. Hãy chọn ma trận khác.");
            }
            return new int[]{a, b, c, d};
        } catch (NumberFormatException ex) {
            throw new IllegalArgumentException("Key Hill phải là 4 số, ví dụ 3,3,2,5");
        }
    }

    private int modularInverse(int value) {
        value = normalize(value);
        for (int candidate = 1; candidate < MOD; candidate++) {
            if ((value * candidate) % MOD == 1) {
                return candidate;
            }
        }
        throw new IllegalArgumentException("Không tìm được nghịch đảo modular cho định thức Hill.");
    }

    private int gcd(int first, int second) {
        int a = Math.abs(first);
        int b = Math.abs(second);
        while (b != 0) {
            int temporary = a % b;
            a = b;
            b = temporary;
        }
        return a;
    }

    private int normalize(int value) {
        int normalized = value % MOD;
        return normalized < 0 ? normalized + MOD : normalized;
    }
}