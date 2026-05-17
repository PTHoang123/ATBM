package com.atbm.service;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;

class BlockCipherServiceTest {
    private final BlockCipherService service = new BlockCipherService();

    @Test
    void shouldEncryptAndDecryptBlowfish() {
        String key = service.generateKey("Blowfish", 128);
        String plainText = "Symmetric encryption round trip.";

        String cipherText = service.encrypt("Blowfish", plainText, key);
        String decrypted = service.decrypt("Blowfish", cipherText, key);

        assertEquals(plainText, decrypted);
    }
}
