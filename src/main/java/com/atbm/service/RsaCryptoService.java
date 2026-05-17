package com.atbm.service;

import javax.crypto.Cipher;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

public class RsaCryptoService implements AsymmetricCryptoService {
    private static final SecureRandom RANDOM = new SecureRandom();
    private static final String ALGORITHM = "RSA";
    private static final String TRANSFORMATION = "RSA/ECB/PKCS1Padding";

    @Override
    public String generateKeyPair(String algorithm, int keyLength) {
        validateAlgorithm(algorithm);
        try {
            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(ALGORITHM);
            keyPairGenerator.initialize(validateKeyLength(keyLength), RANDOM);
            KeyPair keyPair = keyPairGenerator.generateKeyPair();
            return encodeKey(keyPair.getPublic()) + "\n" + encodeKey(keyPair.getPrivate());
        } catch (GeneralSecurityException ex) {
            throw new IllegalArgumentException("Không thể tạo key pair RSA: " + ex.getMessage(), ex);
        }
    }

    @Override
    public String encrypt(String algorithm, String plainText, String publicKey) {
        validateAlgorithm(algorithm);
        try {
            PublicKey key = decodePublicKey(publicKey);
            Cipher cipher = Cipher.getInstance(TRANSFORMATION);
            cipher.init(Cipher.ENCRYPT_MODE, key);

            byte[] plainBytes = plainText.getBytes(StandardCharsets.UTF_8);
            int blockSize = getEncryptBlockSize(key);
            return Base64.getEncoder().encodeToString(processBlocks(cipher, plainBytes, blockSize));
        } catch (IllegalArgumentException ex) {
            throw ex;
        } catch (Exception ex) {
            throw new IllegalArgumentException("Mã hóa RSA thất bại: " + ex.getMessage(), ex);
        }
    }

    @Override
    public String decrypt(String algorithm, String cipherText, String privateKey) {
        return new String(decryptBytes(algorithm, cipherText, privateKey), StandardCharsets.UTF_8);
    }

    public String encryptFile(String algorithm, Path filePath, String publicKey) {
        try {
            byte[] plainBytes = Files.readAllBytes(filePath);
            return encryptBytes(algorithm, plainBytes, publicKey);
        } catch (IOException ex) {
            throw new IllegalArgumentException("Không thể đọc file để mã hóa: " + ex.getMessage(), ex);
        }
    }

    public String decryptFile(String algorithm, Path filePath, String privateKey) {
        try {
            String cipherText = Files.readString(filePath, StandardCharsets.UTF_8);
            return decrypt(algorithm, cipherText, privateKey);
        } catch (IOException ex) {
            throw new IllegalArgumentException("Không thể đọc file để giải mã: " + ex.getMessage(), ex);
        }
    }

    public byte[] decryptFileBytes(String algorithm, Path filePath, String privateKey) {
        try {
            String cipherText = Files.readString(filePath, StandardCharsets.UTF_8);
            return decryptBytes(algorithm, cipherText, privateKey);
        } catch (IOException ex) {
            throw new IllegalArgumentException("Không thể đọc file để giải mã: " + ex.getMessage(), ex);
        }
    }

    private String encryptBytes(String algorithm, byte[] plainBytes, String publicKey) {
        validateAlgorithm(algorithm);
        try {
            PublicKey key = decodePublicKey(publicKey);
            Cipher cipher = Cipher.getInstance(TRANSFORMATION);
            cipher.init(Cipher.ENCRYPT_MODE, key);

            int blockSize = getEncryptBlockSize(key);
            return Base64.getEncoder().encodeToString(processBlocks(cipher, plainBytes, blockSize));
        } catch (IllegalArgumentException ex) {
            throw ex;
        } catch (Exception ex) {
            throw new IllegalArgumentException("Mã hóa RSA thất bại: " + ex.getMessage(), ex);
        }
    }

    private byte[] decryptBytes(String algorithm, String cipherText, String privateKey) {
        validateAlgorithm(algorithm);
        try {
            PrivateKey key = decodePrivateKey(privateKey);
            Cipher cipher = Cipher.getInstance(TRANSFORMATION);
            cipher.init(Cipher.DECRYPT_MODE, key);

            byte[] cipherBytes = Base64.getDecoder().decode(normalizeKeyMaterial(cipherText));
            int blockSize = getDecryptBlockSize(key);
            return processBlocks(cipher, cipherBytes, blockSize);
        } catch (IllegalArgumentException ex) {
            throw ex;
        } catch (Exception ex) {
            throw new IllegalArgumentException("Giải mã RSA thất bại: " + ex.getMessage(), ex);
        }
    }

    private byte[] processBlocks(Cipher cipher, byte[] data, int blockSize) throws Exception {
        ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
        for (int offset = 0; offset < data.length; offset += blockSize) {
            int length = Math.min(blockSize, data.length - offset);
            outputStream.write(cipher.doFinal(data, offset, length));
        }
        return outputStream.toByteArray();
    }

    private PublicKey decodePublicKey(String publicKey) throws GeneralSecurityException {
        byte[] keyBytes = Base64.getDecoder().decode(normalizeKeyMaterial(publicKey));
        X509EncodedKeySpec keySpec = new X509EncodedKeySpec(keyBytes);
        return KeyFactory.getInstance(ALGORITHM).generatePublic(keySpec);
    }

    private PrivateKey decodePrivateKey(String privateKey) throws GeneralSecurityException {
        byte[] keyBytes = Base64.getDecoder().decode(normalizeKeyMaterial(privateKey));
        PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(keyBytes);
        return KeyFactory.getInstance(ALGORITHM).generatePrivate(keySpec);
    }

    private String encodeKey(java.security.Key key) {
        return Base64.getEncoder().encodeToString(key.getEncoded());
    }

    private void validateAlgorithm(String algorithm) {
        if (algorithm == null || !ALGORITHM.equalsIgnoreCase(algorithm.trim())) {
            throw new IllegalArgumentException("Chỉ hỗ trợ thuật toán RSA.");
        }
    }

    private int validateKeyLength(int keyLength) {
        int safeLength = keyLength <= 0 ? 2048 : keyLength;
        if (safeLength != 1024 && safeLength != 2048) {
            throw new IllegalArgumentException("Độ dài key RSA chỉ hỗ trợ 1024 hoặc 2048 bit.");
        }
        return safeLength;
    }

    private int getEncryptBlockSize(PublicKey key) {
        if (key instanceof RSAPublicKey rsaPublicKey) {
            return rsaPublicKey.getModulus().bitLength() / 8 - 11;
        }
        throw new IllegalArgumentException("Key public RSA không hợp lệ.");
    }

    private int getDecryptBlockSize(PrivateKey key) {
        if (key instanceof RSAPrivateKey rsaPrivateKey) {
            return rsaPrivateKey.getModulus().bitLength() / 8;
        }
        throw new IllegalArgumentException("Key private RSA không hợp lệ.");
    }

    private String normalizeKeyMaterial(String keyMaterial) {
        if (keyMaterial == null || keyMaterial.trim().isEmpty()) {
            throw new IllegalArgumentException("Key không được để trống.");
        }
        return keyMaterial.trim();
    }
}
