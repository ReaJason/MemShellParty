package com.reajason.javaweb.memshell;

import com.reajason.javaweb.Server;
import com.reajason.javaweb.memshell.config.InjectorConfig;
import com.reajason.javaweb.memshell.config.ShellConfig;
import com.reajason.javaweb.memshell.shelltool.godzilla.GodzillaConfig;
import com.reajason.javaweb.probe.ProbeContent;
import com.reajason.javaweb.probe.ProbeMethod;
import com.reajason.javaweb.probe.config.ProbeConfig;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

class ProbeModeGenerationTest {

    @Test
    void probeDefaultsToResponseBody() {
        ProbeConfig probe = ProbeConfig.builder()
                .respHeaderName("X-Unused-For-Body")
                .build();

        MemShellResult result = generate(probe);

        assertEquals(ProbeMethod.ResponseBody, result.getShellConfig().getProbe().getProbeMethod());
        assertEquals(ProbeContent.Bytecode, result.getShellConfig().getProbe().getProbeContent());
        assertFalse(classBytes(result).contains("X-Unused-For-Body"));
    }

    @Test
    void responseHeaderProbeUsesConfiguredHeaderName() {
        ProbeConfig probe = ProbeConfig.builder()
                .probeMethod(ProbeMethod.ResponseHeader)
                .probeContent(ProbeContent.Bytecode)
                .respHeaderName("X-Injection-Result")
                .build();

        MemShellResult result = generate(probe);

        assertEquals("X-Injection-Result", result.getShellConfig().getProbe().getRespHeaderName());
        assertTrue(classBytes(result).contains("X-Injection-Result"));
    }

    @Test
    void responseHeaderProbeWritesBackRandomHeaderName() {
        ProbeConfig probe = ProbeConfig.builder()
                .probeMethod(ProbeMethod.ResponseHeader)
                .probeContent(ProbeContent.Bytecode)
                .respHeaderName(" ")
                .build();

        MemShellResult result = generate(probe);

        String headerName = result.getShellConfig().getProbe().getRespHeaderName();
        assertNotNull(headerName);
        assertTrue(headerName.startsWith("X-"), headerName);
        assertTrue(classBytes(result).contains(headerName));
    }

    private static MemShellResult generate(ProbeConfig probe) {
        ShellConfig shellConfig = ShellConfig.builder()
                .server(Server.Tomcat)
                .shellTool(ShellTool.Godzilla)
                .shellType(ShellType.FILTER)
                .probe(probe)
                .build();
        GodzillaConfig shellToolConfig = GodzillaConfig.builder()
                .pass("pass")
                .key("key")
                .headerName("User-Agent")
                .headerValue("test")
                .build();
        return new MemShellGenerator().generate(
                shellConfig, InjectorConfig.builder().build(), shellToolConfig);
    }

    private static String classBytes(MemShellResult result) {
        return new String(result.getInjectorBytes(), StandardCharsets.ISO_8859_1);
    }
}
