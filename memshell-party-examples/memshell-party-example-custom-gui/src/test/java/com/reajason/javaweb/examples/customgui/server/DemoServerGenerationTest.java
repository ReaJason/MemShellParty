package com.reajason.javaweb.examples.customgui.server;

import com.reajason.javaweb.memshell.MemShellGenerator;
import com.reajason.javaweb.memshell.MemShellRegistry;
import com.reajason.javaweb.memshell.MemShellResult;
import com.reajason.javaweb.memshell.ShellTool;
import com.reajason.javaweb.memshell.ShellType;
import com.reajason.javaweb.memshell.config.InjectorConfig;
import com.reajason.javaweb.memshell.config.ShellConfig;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import static org.junit.jupiter.api.Assertions.*;

/**
 * 生成期验证：自定义 server 通过 SPI 被发现、与内置工具的映射求交集、
 * 每种 shellType 都能生成出产物。真实注入与使用见 {@link DemoServerEmbeddedTomcatTest}。
 *
 * @author ReaJason
 */
class DemoServerGenerationTest {

    @Test
    void spiDiscoversDemoServer() {
        // META-INF/services/...ServerProvider 经 ServiceLoader 发现
        assertTrue(MemShellRegistry.getInstance().getSupportedServers().contains(DemoServerProvider.NAME),
                "DemoServletApp provider not registered: " + MemShellRegistry.getInstance().getSupportedServers());
        assertNotNull(MemShellRegistry.getInstance().getServer(DemoServerProvider.NAME));
    }

    @Test
    void onlyMappedShellTypesAreExposed() {
        // 自定义 server 只声明了 Filter/Servlet 注入器，其余类型不进交集
        MemShellRegistry.getInstance().getServer(DemoServerProvider.NAME);
        assertTrue(MemShellRegistry.getInstance().getServer(DemoServerProvider.NAME).getSupportedShellTypes(ShellTool.Command).contains(ShellType.FILTER));
        assertFalse(MemShellRegistry.getInstance().getServer(DemoServerProvider.NAME).getSupportedShellTypes(ShellTool.Command).contains(ShellType.LISTENER));
        assertFalse(MemShellRegistry.getInstance().getServer(DemoServerProvider.NAME).getSupportedShellTypes(ShellTool.Command).contains(ShellType.VALVE));
    }

    @ParameterizedTest
    @ValueSource(strings = {"Filter", "Servlet", "JakartaFilter", "JakartaServlet"})
    void commandGeneratesAcrossMappedShellTypes(String shellType) {
        MemShellResult result = new MemShellGenerator().generate(
                ShellConfig.builder()
                        .server(DemoServerProvider.NAME)
                        .shellTool(ShellTool.Command)
                        .shellType(shellType)
                        .build(),
                InjectorConfig.builder().urlPattern("/*").build(),
                com.reajason.javaweb.memshell.shelltool.command.CommandConfig.builder().paramName("cmd").build());
        assertResultContract(result);
    }

    @Test
    void godzillaGeneratesAcrossMappedShellTypes() {
        MemShellResult result = new MemShellGenerator().generate(
                ShellConfig.builder()
                        .server(DemoServerProvider.NAME)
                        .shellTool(ShellTool.Godzilla)
                        .shellType(ShellType.FILTER)
                        .build(),
                InjectorConfig.builder().urlPattern("/*").build(),
                com.reajason.javaweb.memshell.shelltool.godzilla.GodzillaConfig.builder().pass("pass").key("key").build());
        assertResultContract(result);
    }

    private static void assertResultContract(MemShellResult result) {
        assertNotNull(result);
        assertFalse(result.getInjectorClassName().isEmpty(), "injectorClassName");
        assertFalse(result.getShellClassName().isEmpty(), "shellClassName");
        assertTrue(result.getInjectorBytes().length > 0, "injectorBytes empty");
        assertTrue(result.getShellBytes().length > 0, "shellBytes empty");
        assertEquals(result.getInjectorBytes().length, result.getInjectorSize());
        assertEquals(result.getShellBytes().length, result.getShellSize());
        assertFalse(result.getInjectorBytesBase64Str().isEmpty(), "injectorBytesBase64Str");
    }
}
