package com.reajason.javaweb.antsword;

import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.Test;

/**
 * @author ReaJason
 * @since 2025/2/18
 */
class AntSwordManagerTest {

    @Test
    @Disabled("only for local test")
    void test() {
        AntSwordManager antSwordManager = AntSwordManager.builder()
                .pass("ant")
                .entrypoint("http://localhost:8082/app/ant.jsp").build();
        System.out.println(antSwordManager.getInfo());
    }
}