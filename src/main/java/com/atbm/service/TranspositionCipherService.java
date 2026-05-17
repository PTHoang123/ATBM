package com.atbm.service;

import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;

public class TranspositionCipherService {
    private static final SecureRandom RANDOM = new SecureRandom();

    public String generateKey(int length) {
        int safeLength = Math.max(3, length);
        StringBuilder key = new StringBuilder(safeLength);
        for (int index = 0; index < safeLength; index++) {
            key.append((char) ('A' + RANDOM.nextInt(26)));
        }
        return key.toString();
    }

    public String encrypt(String plainText, String key) {
        String normalizedKey = normalizeKey(key);
        int columns = normalizedKey.length();
        int rows = (int) Math.ceil((double) plainText.length() / columns);

        char[][] matrix = new char[rows][columns];
        int index = 0;
        for (int row = 0; row < rows; row++) {
            for (int column = 0; column < columns; column++) {
                if (index < plainText.length()) {
                    matrix[row][column] = plainText.charAt(index++);
                } else {
                    matrix[row][column] = 'X';
                }
            }
        }

        StringBuilder output = new StringBuilder(rows * columns);
        for (int orderIndex : columnOrder(normalizedKey)) {
            for (int row = 0; row < rows; row++) {
                output.append(matrix[row][orderIndex]);
            }
        }

        return output.toString();
    }

    public String decrypt(String cipherText, String key) {
        String normalizedKey = normalizeKey(key);
        int columns = normalizedKey.length();
        if (cipherText.length() % columns != 0) {
            throw new IllegalArgumentException("Dữ liệu mã hóa hoán vị không hợp lệ.");
        }

        int rows = cipherText.length() / columns;
        char[][] matrix = new char[rows][columns];
        List<Integer> order = columnOrder(normalizedKey);
        int index = 0;

        for (int orderIndex : order) {
            for (int row = 0; row < rows; row++) {
                matrix[row][orderIndex] = cipherText.charAt(index++);
            }
        }

        StringBuilder output = new StringBuilder(cipherText.length());
        for (int row = 0; row < rows; row++) {
            for (int column = 0; column < columns; column++) {
                output.append(matrix[row][column]);
            }
        }

        return output.toString();
    }

    private String normalizeKey(String key) {
        if (key == null) {
            throw new IllegalArgumentException("Vui lòng nhập key hoán vị hoặc bật tự tạo key.");
        }

        String normalized = key.replaceAll("[^A-Za-z]", "").toUpperCase().trim();
        if (normalized.length() < 3) {
            throw new IllegalArgumentException("Key hoán vị phải có ít nhất 3 ký tự chữ cái.");
        }
        return normalized;
    }

    private List<Integer> columnOrder(String key) {
        List<Integer> order = new ArrayList<>();
        for (int index = 0; index < key.length(); index++) {
            order.add(index);
        }

        order.sort(Comparator.comparingInt((Integer index) -> key.charAt(index)).thenComparingInt(index -> index));
        return order;
    }
}