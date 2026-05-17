package com.atbm.service;

public interface AsymmetricCryptoService {
    String generateKeyPair(String algorithm, int keyLength);

    String encrypt(String algorithm, String plainText, String publicKey);

    String decrypt(String algorithm, String cipherText, String privateKey);
}
