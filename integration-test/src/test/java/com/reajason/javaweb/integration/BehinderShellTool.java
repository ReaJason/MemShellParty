package com.reajason.javaweb.integration;

import com.reajason.javaweb.behinder.BehinderManager;
import com.reajason.javaweb.memshell.config.BehinderConfig;

import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * @author ReaJason
 * @since 2024/11/30
 */
public class BehinderShellTool {

    public static void testIsOk(String entrypoint, BehinderConfig shellConfig) {
        BehinderManager behinderManager = BehinderManager.builder()
                .entrypoint(entrypoint).pass(shellConfig.getPass())
                .header(shellConfig.getHeaderName()
                        , shellConfig.getHeaderValue()).build();
        assertTrue(behinderManager.test());
    }
}
