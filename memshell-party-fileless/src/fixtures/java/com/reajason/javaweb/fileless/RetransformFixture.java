package com.reajason.javaweb.fileless;

final class RetransformFixture {
    private RetransformFixture() {
    }

    static byte[] replaceBipushReturn(byte[] classBytes, int original, int replacement) {
        int matches = 0;
        int matchOffset = -1;
        for (int i = 0; i < classBytes.length - 2; i++) {
            if (classBytes[i] == 16 && classBytes[i + 1] == (byte) original
                    && classBytes[i + 2] == (byte) 0xac) {
                matches++;
                matchOffset = i;
            }
        }
        if (matches != 1) {
            throw new IllegalArgumentException("Expected one fixture return instruction, found " + matches);
        }
        byte[] transformed = new byte[classBytes.length];
        System.arraycopy(classBytes, 0, transformed, 0, classBytes.length);
        transformed[matchOffset + 1] = (byte) replacement;
        return transformed;
    }
}
