package com.reajason.javaweb.behinder;

import org.junit.jupiter.api.Test;

/**
 * @author ReaJason
 * @since 2024/12/21
 */
class BehinderManagerTest {

    @Test
    void test() {
        BehinderManager behinderManager = BehinderManager.builder()
                .entrypoint("http://localhost:8080/test")
                .pass("pass")
                .header("User-Agent", "BehinderinterceptorBase64").build();
        behinderManager.test();
    }
}