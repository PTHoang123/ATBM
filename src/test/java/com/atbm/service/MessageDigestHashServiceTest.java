package com.atbm.service;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import static org.junit.jupiter.api.Assertions.assertEquals;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;

class MessageDigestHashServiceTest {
    private final MessageDigestHashService service = new MessageDigestHashService();
    @TempDir
    Path tempDir;

    @Test
    void shouldHashWithMd5() {
        assertEquals("900150983cd24fb0d6963f7d28e17f72", service.hash("MD5", "abc"));
    }

    @Test
    void shouldHashWithSha256() {
        assertEquals(
                "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
                service.hash("SHA-256", "abc")
        );
    }

    @Test
    void shouldHashWithBlake2b256() {
        assertEquals(
                "bddd813c634239723171ef3fee98579b94964e3bb1cb3e427262c8c068d52319",
                service.hash("BLAKE2b-256", "abc")
        );
    }

    @Test
    void shouldHashFileContent() throws Exception {
        Path file = tempDir.resolve("sample.txt");
        Files.writeString(file, "abc", StandardCharsets.UTF_8);

        assertEquals("900150983cd24fb0d6963f7d28e17f72", service.hashFile("MD5", file));
    }
}
