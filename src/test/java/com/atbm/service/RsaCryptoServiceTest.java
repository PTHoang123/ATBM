package com.atbm.service;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertArrayEquals;

class RsaCryptoServiceTest {
    private final RsaCryptoService service = new RsaCryptoService();
    @TempDir
    Path tempDir;

    @Test
    void shouldEncryptAndDecryptLongTextWithGeneratedKeyPair() {
        String generated = service.generateKeyPair("RSA", 2048);
        String[] pair = generated.split("\\R", 2);
        assertEquals(2, pair.length);

        String plainText = "Xin chào RSA, đây là một thông điệp dài hơn một khối để kiểm tra chia khối.";
        String cipherText = service.encrypt("RSA", plainText, pair[0]);
        String decrypted = service.decrypt("RSA", cipherText, pair[1]);

        assertEquals(plainText, decrypted);
        assertNotNull(cipherText);
    }

    @Test
    void shouldGenerate1024BitKeyPair() {
        String generated = service.generateKeyPair("RSA", 1024);

        assertEquals(2, generated.split("\\R", 2).length);
    }

    @Test
    void shouldRejectUnsupportedAlgorithm() {
        org.junit.jupiter.api.Assertions.assertThrows(IllegalArgumentException.class, () ->
                service.generateKeyPair("DSA", 2048));
    }

    @Test
    void shouldRejectUnsupportedKeyLength() {
        org.junit.jupiter.api.Assertions.assertThrows(IllegalArgumentException.class, () ->
                service.generateKeyPair("RSA", 1536));
    }

    @Test
    void shouldEncryptAndDecryptFileContent() throws Exception {
        String generated = service.generateKeyPair("RSA", 2048);
        String[] pair = generated.split("\\R", 2);

        Path plainFile = tempDir.resolve("plain.txt");
        String plainText = "Nội dung file RSA để kiểm tra.";
        Files.writeString(plainFile, plainText, StandardCharsets.UTF_8);

        String cipherText = service.encryptFile("RSA", plainFile, pair[0]);
        Path cipherFile = tempDir.resolve("cipher.txt");
        Files.writeString(cipherFile, cipherText, StandardCharsets.UTF_8);

        String decrypted = service.decryptFile("RSA", cipherFile, pair[1]);

        assertEquals(plainText, decrypted);
    }

    @Test
    void shouldEncryptAndDecryptBinaryFileBytes() throws Exception {
        String generated = service.generateKeyPair("RSA", 2048);
        String[] pair = generated.split("\\R", 2);

        Path binaryFile = tempDir.resolve("sample.bin");
        byte[] originalBytes = new byte[]{0, 1, 2, 3, 4, 5, -1, -2, 10, 20};
        Files.write(binaryFile, originalBytes);

        String cipherText = service.encryptFile("RSA", binaryFile, pair[0]);
        Path cipherFile = tempDir.resolve("sample.enc");
        Files.writeString(cipherFile, cipherText, StandardCharsets.UTF_8);

        byte[] decryptedBytes = service.decryptFileBytes("RSA", cipherFile, pair[1]);

        assertArrayEquals(originalBytes, decryptedBytes);
    }
}
