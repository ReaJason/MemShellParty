package com.reajason.javaweb.memshell.config;

import com.reajason.javaweb.memshell.config.GodzillaConfig;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;

/**
 * @author ReaJason
 * @since 2024/12/5
 */
class GodzillaShellConfigTest {

    @Test
    void test() {
        GodzillaConfig shellConfig = GodzillaConfig.builder()
                .pass("pass").build();
        assertEquals("key", shellConfig.getKey());
    }
}