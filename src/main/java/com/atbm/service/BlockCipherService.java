package com.atbm.service;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.GeneralSecurityException;
import java.security.Security;
import java.security.SecureRandom;
import java.util.Base64;

public class BlockCipherService {
    private static final SecureRandom RANDOM = new SecureRandom();

    static {
        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
            Security.addProvider(new BouncyCastleProvider());
        }
    }

    public String generateKey(String algorithm, int keySizeBits) {
        try {
            KeyGenerator keyGenerator = createKeyGenerator(algorithm);
            keyGenerator.init(validateKeySize(algorithm, keySizeBits), RANDOM);
            SecretKey secretKey = keyGenerator.generateKey();
            return Base64.getEncoder().encodeToString(secretKey.getEncoded());
        } catch (GeneralSecurityException ex) {
            throw new IllegalArgumentException("Không thể tạo key cho " + algorithm + ": " + ex.getMessage(), ex);
        }
    }

    public String encrypt(String algorithm, String plainText, String base64Key) {
        return encrypt(algorithm, plainText, base64Key, PaddingMode.PKCS5);
    }

    public String encrypt(String algorithm, String plainText, String base64Key, PaddingMode paddingMode) {
        try {
            byte[] keyBytes = Base64.getDecoder().decode(normalizeBase64(base64Key));
            SecretKeySpec secretKey = new SecretKeySpec(keyBytes, algorithm);
            Cipher cipher = createCipherNoCustomPadding(algorithm, paddingMode.getJavaPaddingName());
            byte[] iv = new byte[cipher.getBlockSize()];
            RANDOM.nextBytes(iv);
            cipher.init(Cipher.ENCRYPT_MODE, secretKey, new IvParameterSpec(iv));
            
            byte[] plainBytes = plainText.getBytes(java.nio.charset.StandardCharsets.UTF_8);
            
            // Handle custom zero padding
            if (paddingMode == PaddingMode.ZERO) {
                plainBytes = applyZeroPadding(plainBytes, cipher.getBlockSize());
            }
            
            byte[] cipherBytes = cipher.doFinal(plainBytes);
            
            byte[] payload = new byte[iv.length + cipherBytes.length];
            System.arraycopy(iv, 0, payload, 0, iv.length);
            System.arraycopy(cipherBytes, 0, payload, iv.length, cipherBytes.length);
            return Base64.getEncoder().encodeToString(payload);
        } catch (IllegalArgumentException ex) {
            throw ex;
        } catch (Exception ex) {
            throw new IllegalArgumentException("Mã hóa " + algorithm + " thất bại: " + ex.getMessage(), ex);
        }
    }

    public String decrypt(String algorithm, String cipherText, String base64Key) {
        return decrypt(algorithm, cipherText, base64Key, PaddingMode.PKCS5);
    }

    public String decrypt(String algorithm, String cipherText, String base64Key, PaddingMode paddingMode) {
        try {
            byte[] keyBytes = Base64.getDecoder().decode(normalizeBase64(base64Key));
            SecretKeySpec secretKey = new SecretKeySpec(keyBytes, algorithm);
            Cipher cipher = createCipherNoCustomPadding(algorithm, paddingMode.getJavaPaddingName());
            byte[] payload = Base64.getDecoder().decode(cipherText.trim());
            int ivLength = cipher.getBlockSize();
            if (payload.length < ivLength) {
                throw new IllegalArgumentException("Dữ liệu mã hóa không hợp lệ.");
            }

            byte[] iv = new byte[ivLength];
            byte[] ciphertextBytes = new byte[payload.length - ivLength];
            System.arraycopy(payload, 0, iv, 0, ivLength);
            System.arraycopy(payload, ivLength, ciphertextBytes, 0, ciphertextBytes.length);

            cipher.init(Cipher.DECRYPT_MODE, secretKey, new IvParameterSpec(iv));
            byte[] plainBytes = cipher.doFinal(ciphertextBytes);
            
            // Remove zero padding if used
            if (paddingMode == PaddingMode.ZERO) {
                plainBytes = removeZeroPadding(plainBytes);
            }
            
            return new String(plainBytes, java.nio.charset.StandardCharsets.UTF_8);
        } catch (IllegalArgumentException ex) {
            throw ex;
        } catch (Exception ex) {
            throw new IllegalArgumentException("Giải mã " + algorithm + " thất bại: " + ex.getMessage(), ex);
        }
    }

    private Cipher createCipherNoCustomPadding(String algorithm, String paddingName) throws GeneralSecurityException {
        String transformation = algorithm + "/CBC/" + paddingName;
        if (isCamellia(algorithm)) {
            return Cipher.getInstance(transformation, BouncyCastleProvider.PROVIDER_NAME);
        }
        return Cipher.getInstance(transformation);
    }

    private byte[] applyZeroPadding(byte[] data, int blockSize) {
        int padding = blockSize - (data.length % blockSize);
        if (padding == 0) {
            padding = blockSize;
        }
        byte[] padded = new byte[data.length + padding];
        System.arraycopy(data, 0, padded, 0, data.length);
        // Rest are zeros (already initialized)
        return padded;
    }

    private byte[] removeZeroPadding(byte[] data) {
        int i = data.length - 1;
        while (i >= 0 && data[i] == 0) {
            i--;
        }
        byte[] result = new byte[i + 1];
        System.arraycopy(data, 0, result, 0, i + 1);
        return result;
    }

    private KeyGenerator createKeyGenerator(String algorithm) throws GeneralSecurityException {
        if (isCamellia(algorithm)) {
            return KeyGenerator.getInstance(algorithm, BouncyCastleProvider.PROVIDER_NAME);
        }
        return KeyGenerator.getInstance(algorithm);
    }

    private boolean isCamellia(String algorithm) {
        return "Camellia".equalsIgnoreCase(algorithm);
    }

    private int validateKeySize(String algorithm, int keySizeBits) {
        int size = keySizeBits;
        if (size <= 0) {
            size = isCamellia(algorithm) ? 128 : 128;
        }

        if (isCamellia(algorithm)) {
            if (size != 128 && size != 192 && size != 256) {
                throw new IllegalArgumentException("Camellia chỉ hỗ trợ key 128, 192 hoặc 256 bit.");
            }
            return size;
        }

        if (size < 32 || size > 448) {
            throw new IllegalArgumentException("Blowfish hỗ trợ key từ 32 đến 448 bit.");
        }

        return size;
    }

    private String normalizeBase64(String base64Key) {
        if (base64Key == null || base64Key.trim().isEmpty()) {
            throw new IllegalArgumentException("Key không được để trống.");
        }
        return base64Key.trim();
    }
}