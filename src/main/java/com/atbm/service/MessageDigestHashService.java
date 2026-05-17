package com.atbm.service;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.Security;
import java.io.IOException;

public class MessageDigestHashService implements HashService {
    static {
        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
            Security.addProvider(new BouncyCastleProvider());
        }
    }

    @Override
    public String hash(String algorithm, String input) {
        try {
            MessageDigest messageDigest = createMessageDigest(algorithm);
            byte[] digest = messageDigest.digest(input.getBytes(StandardCharsets.UTF_8));
            return toHex(digest);
        } catch (NoSuchAlgorithmException ex) {
            throw new IllegalArgumentException("Thuật toán hash không được hỗ trợ: " + algorithm, ex);
        }
    }

    public String hashFile(String algorithm, Path filePath) {
        try {
            MessageDigest messageDigest = createMessageDigest(algorithm);
            byte[] buffer = new byte[8192];
            try (var inputStream = Files.newInputStream(filePath)) {
                int read;
                while ((read = inputStream.read(buffer)) != -1) {
                    messageDigest.update(buffer, 0, read);
                }
            }
            return toHex(messageDigest.digest());
        } catch (IOException ex) {
            throw new IllegalArgumentException("Không thể đọc file để băm: " + ex.getMessage(), ex);
        } catch (NoSuchAlgorithmException ex) {
            throw new IllegalArgumentException("Thuật toán hash không được hỗ trợ: " + algorithm, ex);
        }
    }

    private MessageDigest createMessageDigest(String algorithm) throws NoSuchAlgorithmException {
        String normalized = normalizeAlgorithm(algorithm);
        try {
            return MessageDigest.getInstance(normalized);
        } catch (NoSuchAlgorithmException ex) {
            return MessageDigest.getInstance(
                    toBouncyCastleAlgorithm(normalized),
                    Security.getProvider(BouncyCastleProvider.PROVIDER_NAME)
            );
        }
    }

    private String normalizeAlgorithm(String algorithm) {
        if (algorithm == null || algorithm.trim().isEmpty()) {
            throw new IllegalArgumentException("Vui lòng chọn thuật toán hash.");
        }

        return algorithm.trim().replace("_", "-");
    }

    private String toBouncyCastleAlgorithm(String algorithm) {
        String upper = algorithm.toUpperCase();
        if ("BLAKE2B-256".equals(upper)) {
            return "BLAKE2B-256";
        }
        return algorithm;
    }

    private String toHex(byte[] bytes) {
        StringBuilder builder = new StringBuilder(bytes.length * 2);
        for (byte value : bytes) {
            builder.append(String.format("%02x", value));
        }
        return builder.toString();
    }
}
