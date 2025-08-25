package com.reajason.javaweb.memshell.config;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertNotNull;

/**
 * @author ReaJason
 * @since 2025/8/25
 */
class GodzillaConfigTest {

    @Test
    void testNull() {
        GodzillaConfig godzillaConfig = GodzillaConfig.builder()
                .pass(null)
                .key("")
                .headerName(null)
                .headerValue("")
                .build();
        assertNotNull(godzillaConfig.getPass());
        assertNotNull(godzillaConfig.getKey());
        assertNotNull(godzillaConfig.getHeaderName());
        assertNotNull(godzillaConfig.getHeaderValue());
    }
}