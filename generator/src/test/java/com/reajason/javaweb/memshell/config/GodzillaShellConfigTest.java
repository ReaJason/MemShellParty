package com.reajason.javaweb.memshell.config;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;

/**
 * @author ReaJason
 * @since 2024/12/5
 */
class GodzillaShellConfigTest {

    @Test
    void test() {
        GodzillaConfig shellConfig = GodzillaConfig.builder()
                .pass("pass").build();
        assertEquals("pass", shellConfig.getPass());
        assertNotEquals("key", shellConfig.getKey());
    }
}