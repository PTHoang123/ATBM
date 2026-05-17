package com.atbm.service;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class RsaDigitalSignatureServiceTest {
    private final RsaCryptoService rsaCryptoService = new RsaCryptoService();
    private final RsaDigitalSignatureService signatureService = new RsaDigitalSignatureService();

    @Test
    void shouldSignAndVerifyData() {
        String[] pair = rsaCryptoService.generateKeyPair("RSA", 2048).split("\\R", 2);
        String signature = signatureService.sign("RSA Signature", "du lieu can ky", pair[1]);

        assertTrue(signatureService.verify("RSA Signature", "du lieu can ky", signature, pair[0]));
    }

    @Test
    void shouldRejectTamperedData() {
        String[] pair = rsaCryptoService.generateKeyPair("RSA", 2048).split("\\R", 2);
        String signature = signatureService.sign("RSA Signature", "du lieu can ky", pair[1]);

        assertFalse(signatureService.verify("RSA Signature", "du lieu bi sua", signature, pair[0]));
    }
}
