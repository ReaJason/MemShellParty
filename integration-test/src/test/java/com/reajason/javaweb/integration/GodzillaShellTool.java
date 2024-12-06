package com.reajason.javaweb.integration;

import com.reajason.javaweb.GeneratorMain;
import com.reajason.javaweb.config.*;
import com.reajason.javaweb.godzilla.GodzillaManager;
import com.reajason.javaweb.memsell.packer.Packer;
import com.reajason.javaweb.memsell.tomcat.TomcatShell;

import java.io.IOException;

import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * @author ReaJason
 * @since 2024/11/30
 */
public class GodzillaShellTool {

    public static void testIsOk(String entrypoint, GodzillaConfig shellConfig) {
        try (GodzillaManager godzillaManager = GodzillaManager.builder()
                .entrypoint(entrypoint).pass(shellConfig.getPass())
                .key(shellConfig.getKey()).header(shellConfig.getHeaderName()
                        , shellConfig.getHeaderValue()).build()) {
            assertTrue(godzillaManager.start());
            assertTrue(godzillaManager.test());
        } catch (IOException e) {
            e.printStackTrace();
        }
    }
}
