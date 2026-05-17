package com.atbm.service;

import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

public class RsaDigitalSignatureService implements DigitalSignatureService {
    private static final SecureRandom RANDOM = new SecureRandom();
    private static final String ALGORITHM = "SHA256withRSA";

    @Override
    public String sign(String algorithm, String input, String privateKey) {
        validateAlgorithm(algorithm);
        try {
            Signature signature = Signature.getInstance(ALGORITHM);
            signature.initSign(decodePrivateKey(privateKey), RANDOM);
            signature.update(input.getBytes(StandardCharsets.UTF_8));
            return Base64.getEncoder().encodeToString(signature.sign());
        } catch (IllegalArgumentException ex) {
            throw ex;
        } catch (GeneralSecurityException ex) {
            throw new IllegalArgumentException("Ký RSA thất bại: " + ex.getMessage(), ex);
        }
    }

    @Override
    public boolean verify(String algorithm, String input, String signatureText, String publicKey) {
        validateAlgorithm(algorithm);
        try {
            Signature signature = Signature.getInstance(ALGORITHM);
            signature.initVerify(decodePublicKey(publicKey));
            signature.update(input.getBytes(StandardCharsets.UTF_8));
            return signature.verify(Base64.getDecoder().decode(normalize(signatureText)));
        } catch (IllegalArgumentException ex) {
            throw ex;
        } catch (GeneralSecurityException ex) {
            throw new IllegalArgumentException("Xác minh chữ ký RSA thất bại: " + ex.getMessage(), ex);
        }
    }

    private void validateAlgorithm(String algorithm) {
        if (algorithm == null || !algorithm.toLowerCase().contains("rsa")) {
            throw new IllegalArgumentException("Chỉ hỗ trợ chữ ký RSA.");
        }
    }

    private PrivateKey decodePrivateKey(String privateKey) throws GeneralSecurityException {
        byte[] keyBytes = Base64.getDecoder().decode(normalize(privateKey));
        return KeyFactory.getInstance("RSA").generatePrivate(new PKCS8EncodedKeySpec(keyBytes));
    }

    private PublicKey decodePublicKey(String publicKey) throws GeneralSecurityException {
        byte[] keyBytes = Base64.getDecoder().decode(normalize(publicKey));
        return KeyFactory.getInstance("RSA").generatePublic(new X509EncodedKeySpec(keyBytes));
    }

    private String normalize(String value) {
        if (value == null || value.trim().isEmpty()) {
            throw new IllegalArgumentException("Key hoặc chữ ký không được để trống.");
        }
        return value.trim();
    }
}
