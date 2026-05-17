package com.atbm.service;

public interface DigitalSignatureService {
    String sign(String algorithm, String input, String privateKey);

    boolean verify(String algorithm, String input, String signature, String publicKey);
}
