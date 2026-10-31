package com.reajason.javaweb.memshell.obfuscation;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class ObfuscationInfoTest {

    @Test
    void shouldCalculateTotalSizes() {
        ObfuscationInfo info = ObfuscationInfo.builder()
                .enabled(true)
                .originalShellSize(1000)
                .obfuscatedShellSize(1500)
                .originalInjectorSize(2000)
                .obfuscatedInjectorSize(3000)
                .build();

        assertEquals(3000L, info.getOriginalSize());
        assertEquals(4500L, info.getObfuscatedSize());
    }
}
