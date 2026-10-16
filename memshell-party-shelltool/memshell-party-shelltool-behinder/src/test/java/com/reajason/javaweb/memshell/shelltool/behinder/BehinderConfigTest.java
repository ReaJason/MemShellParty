package com.reajason.javaweb.memshell.shelltool.behinder;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertNotNull;

/**
 * @author ReaJason
 * @since 2025/8/26
 */
class BehinderConfigTest {

    @Test
    void test() {
        BehinderConfig behinderConfig = BehinderConfig.builder()
                .pass(null)
                .headerName("")
                .headerValue("").build();
        assertNotNull(behinderConfig.getPass());
        assertNotNull(behinderConfig.getHeaderName());
        assertNotNull(behinderConfig.getHeaderValue());
    }

}