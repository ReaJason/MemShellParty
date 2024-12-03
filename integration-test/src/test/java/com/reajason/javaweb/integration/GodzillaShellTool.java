package com.reajason.javaweb.integration;

import com.reajason.javaweb.GeneratorMain;
import com.reajason.javaweb.config.GenerateResult;
import com.reajason.javaweb.config.GodzillaShellConfig;
import com.reajason.javaweb.config.Server;
import com.reajason.javaweb.config.ShellTool;
import com.reajason.javaweb.godzilla.GodzillaManager;
import com.reajason.javaweb.memsell.packer.Packer;

import java.io.IOException;

import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * @author ReaJason
 * @since 2024/11/30
 */
public class GodzillaShellTool {

    public static String generate(Server server, GodzillaShellConfig config, String shellType, int targetJdkVersion, Packer.INSTANCE packer) {
        ShellTool shellTool = ShellTool.Godzilla;
        GenerateResult generateResult = GeneratorMain.generate(server, shellTool, shellType, config, targetJdkVersion);
        return new String(packer.getPacker().pack(generateResult));
    }

    public static String generateJSP(Server server, GodzillaShellConfig config, String shellType, int targetJdkVersion) {
        ShellTool shellTool = ShellTool.Godzilla;
        GenerateResult generateResult = GeneratorMain.generate(server, shellTool, shellType, config, targetJdkVersion);
        return new String(Packer.INSTANCE.JSP.getPacker().pack(generateResult));
    }

    public static String generateJS(Server server, GodzillaShellConfig config, String shellType, int targetJdkVersion) {
        ShellTool shellTool = ShellTool.Godzilla;
        GenerateResult generateResult = GeneratorMain.generate(server, shellTool, shellType, config, targetJdkVersion);
        return new String(Packer.INSTANCE.ScriptEngine.getPacker().pack(generateResult));
    }

    public static void testIsOk(String entrypoint, GodzillaShellConfig shellConfig) {
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
