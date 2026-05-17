package com.atbm.service;

public enum PaddingMode {
    PKCS5("PKCS5Padding", "PKCS5"),
    PKCS7("PKCS7Padding", "PKCS7"),
    NO_PADDING("NoPadding", "No Padding"),
    ISO10126("ISO10126Padding", "ISO10126"),
    ZERO("ZeroPadding", "Zero Padding (Custom)");

    private final String javaPaddingName;
    private final String displayName;

    PaddingMode(String javaPaddingName, String displayName) {
        this.javaPaddingName = javaPaddingName;
        this.displayName = displayName;
    }

    public String getJavaPaddingName() {
        return javaPaddingName;
    }

    public String getDisplayName() {
        return displayName;
    }

    public static PaddingMode fromDisplayName(String displayName) {
        for (PaddingMode mode : PaddingMode.values()) {
            if (mode.displayName.equals(displayName)) {
                return mode;
            }
        }
        return PKCS5;
    }

    @Override
    public String toString() {
        return displayName;
    }
}
