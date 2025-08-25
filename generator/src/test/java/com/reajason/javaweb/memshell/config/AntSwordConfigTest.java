package com.reajason.javaweb.memshell.config;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertNotNull;

/**
 * @author ReaJason
 * @since 2025/8/26
 */
class AntSwordConfigTest {

    @Test
    void test() {
        AntSwordConfig antSwordConfig = AntSwordConfig.builder()
                .pass("")
                .headerName(null)
                .headerValue("").build();
        assertNotNull(antSwordConfig.getPass());
        assertNotNull(antSwordConfig.getHeaderName());
        assertNotNull(antSwordConfig.getHeaderValue());
    }
}