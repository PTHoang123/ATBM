package com.atbm.service;

import java.security.SecureRandom;

public class AffineCipherService {
    private static final SecureRandom RANDOM = new SecureRandom();
    private static final int MOD = 26;
    private static final int[] VALID_A_VALUES = {1, 3, 5, 7, 9, 11, 15, 17, 19, 21, 23, 25};

    public String generateKey() {
        int a = VALID_A_VALUES[RANDOM.nextInt(VALID_A_VALUES.length)];
        int b = RANDOM.nextInt(MOD);
        return a + "," + b;
    }

    public String encrypt(String plainText, String key) {
        int[] parsedKey = parseKey(key);
        int a = parsedKey[0];
        int b = parsedKey[1];
        StringBuilder output = new StringBuilder(plainText.length());

        for (char ch : plainText.toCharArray()) {
            if (Character.isLetter(ch)) {
                boolean lowerCase = Character.isLowerCase(ch);
                int base = lowerCase ? 'a' : 'A';
                int x = Character.toUpperCase(ch) - 'A';
                int cipherIndex = (a * x + b) % MOD;
                output.append((char) (base + cipherIndex));
            } else {
                output.append(ch);
            }
        }

        return output.toString();
    }

    public String decrypt(String cipherText, String key) {
        int[] parsedKey = parseKey(key);
        int a = parsedKey[0];
        int b = parsedKey[1];
        int inverseA = modularInverse(a);
        StringBuilder output = new StringBuilder(cipherText.length());

        for (char ch : cipherText.toCharArray()) {
            if (Character.isLetter(ch)) {
                boolean lowerCase = Character.isLowerCase(ch);
                int base = lowerCase ? 'a' : 'A';
                int y = Character.toUpperCase(ch) - 'A';
                int plainIndex = inverseA * (y - b);
                plainIndex %= MOD;
                if (plainIndex < 0) {
                    plainIndex += MOD;
                }
                output.append((char) (base + plainIndex));
            } else {
                output.append(ch);
            }
        }

        return output.toString();
    }

    private int[] parseKey(String key) {
        if (key == null || key.trim().isEmpty()) {
            throw new IllegalArgumentException("Vui lòng nhập key Affine dạng a,b hoặc bật tự tạo key.");
        }

        String normalized = key.trim().replace(" ", "");
        String[] parts = normalized.split("[,;:]");
        if (parts.length != 2) {
            throw new IllegalArgumentException("Key Affine phải có dạng a,b. Ví dụ: 5,8");
        }

        try {
            int a = normalize(Integer.parseInt(parts[0]));
            int b = normalize(Integer.parseInt(parts[1]));
            if (gcd(a, MOD) != 1) {
                throw new IllegalArgumentException("a phải nguyên tố cùng nhau với 26. Chọn 1,3,5,7,9,11,15,17,19,21,23,25.");
            }
            return new int[]{a, b};
        } catch (NumberFormatException ex) {
            throw new IllegalArgumentException("Key Affine phải là 2 số, ví dụ 5,8");
        }
    }

    private int modularInverse(int value) {
        value = normalize(value);
        for (int i = 1; i < MOD; i++) {
            if ((value * i) % MOD == 1) {
                return i;
            }
        }
        throw new IllegalArgumentException("Không tìm được nghịch đảo modular cho a.");
    }

    private int gcd(int first, int second) {
        int a = Math.abs(first);
        int b = Math.abs(second);
        if(b == 0){
            return a;
        }
        return gcd(b, a % b);
    }

    private int normalize(int value) {
        int normalized = value % MOD;
        return normalized < 0 ? normalized + MOD : normalized;
    }
}