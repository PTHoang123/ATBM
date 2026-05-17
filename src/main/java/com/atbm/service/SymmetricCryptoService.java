package com.atbm.service;

public interface SymmetricCryptoService {
    String generateKey(String algorithm, int keyLength);

    String encrypt(String algorithm, String plainText, String key);

    String decrypt(String algorithm, String cipherText, String key);
}
