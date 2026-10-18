package com.reajason.javaweb.examples.tongweb;

import com.reajason.javaweb.Server;
import com.reajason.javaweb.memshell.MemShellGenerator;
import com.reajason.javaweb.memshell.MemShellRegistry;
import com.reajason.javaweb.memshell.MemShellResult;
import com.reajason.javaweb.memshell.ShellTool;
import com.reajason.javaweb.memshell.ShellType;
import com.reajason.javaweb.memshell.config.InjectorConfig;
import com.reajason.javaweb.memshell.config.ShellConfig;
import com.reajason.javaweb.memshell.config.ShellToolConfig;
import com.reajason.javaweb.memshell.custom.CustomConfig;
import com.reajason.javaweb.memshell.shelltool.godzilla.GodzillaConfig;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import java.util.Base64;
import java.util.HashMap;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Pins the TongWebExploit usage of MemShellParty: TongWeb server, the seven shell
 * tools it offers, and the shell types it exposes (Filter, Listener, Valve,
 * AgentFilterChain, AgentContextValve). If a refactor breaks SPI discovery, module
 * wiring or the generation result contract, this test fails.
 *
 * @author ReaJason
 * @since 3.0.0
 */
class TongWebMemShellUsageTest {

    /**
     * TongWebExploit's supported matrix:
     * tools = Godzilla(default), Behinder, Command, Suo5, AntSword, NeoreGeorg, Custom
     * shellTypes = Filter(default), Servlet*, Listener, Valve, AgentFilterChain, AgentContextValve
     * (* Servlet never had a TongWeb injector and fails in 2.x as well)
     */
    private static final String[] TOOLS = {
            ShellTool.Godzilla, ShellTool.Behinder, ShellTool.Command, ShellTool.Suo5,
            ShellTool.AntSword, ShellTool.NeoreGeorg
    };

    private static final String[] TONGWEB_SHELL_TYPES = {
            ShellType.FILTER, ShellType.LISTENER, ShellType.VALVE,
            ShellType.AGENT_FILTER_CHAIN, ShellType.CATALINA_AGENT_CONTEXT_VALVE
    };

    @Test
    void spiDiscoversTongWebAndAllTools() {
        // server and tool providers are discovered through ServiceLoader, so this
        // only passes when META-INF/services entries survive packaging (shade: merge them!)
        assertTrue(MemShellRegistry.getInstance().getSupportedServers().contains(Server.TongWeb),
                "TongWeb server provider not registered: " + MemShellRegistry.getInstance().getSupportedServers());
        for (String tool : TOOLS) {
            assertTrue(MemShellRegistry.getInstance().getSupportedTools().contains(tool),
                    tool + " provider not registered: " + MemShellRegistry.getInstance().getSupportedTools());
        }
        assertTrue(MemShellRegistry.getInstance().getSupportedTools().contains(ShellTool.Custom));
    }

    @Test
    void typedBuilderParityWith2x() {
        // the exact call TongWebExploit's MemShellPartyArtifactFactory makes (2.x),
        // with only the GodzillaConfig import moved to its shell-tool module
        ShellConfig shellConfig = ShellConfig.builder()
                .server(Server.TongWeb)
                .serverVersion("7")
                .shellTool(ShellTool.Godzilla)
                .shellType(ShellType.FILTER)
                .shrink(true)
                .debug(false)
                .probe(false)
                .lambdaSuffix(false)
                .jakarta(false)
                .byPassJavaModule(false)
                .build();
        InjectorConfig injectorConfig = InjectorConfig.builder()
                .urlPattern("/*")
                .staticInitialize(false)
                .build();
        GodzillaConfig godzillaConfig = GodzillaConfig.builder()
                .pass("pass")
                .key("key")
                .build();

        MemShellResult result = new MemShellGenerator().generate(shellConfig, injectorConfig, godzillaConfig);

        assertResultContract(result);
        // connection-info readback, as TongWebExploit does for its artifact metadata
        GodzillaConfig built = (GodzillaConfig) result.getShellToolConfig();
        assertEquals("pass", built.getPass());
        assertEquals("key", built.getKey());
        assertNotNull(built.getHeaderName());
        assertNotNull(built.getHeaderValue());
    }

    @ParameterizedTest
    @ValueSource(strings = {"Filter", "Listener", "Valve", "AgentFilterChain", "AgentContextValve"})
    void godzillaAcrossTongWebShellTypes(String shellType) {
        MemShellResult result = generate(ShellTool.Godzilla, shellType, defaultParams());
        assertResultContract(result);
    }

    @Test
    void godzillaWithDynamicParams() {
        // the Map overload replaces the per-tool if/else over config builders;
        // blanks keep defaults, params the tool does not declare are rejected
        MemShellResult result = generate(ShellTool.Godzilla, ShellType.FILTER, defaultParams());
        assertResultContract(result);
    }

    @Test
    void suo5Resolves() {
        assertNotNull(MemShellRegistry.getInstance().getToolProvider(ShellTool.Suo5));
        assertNull(MemShellRegistry.getInstance().getToolProvider("Suo5v2"));
    }

    @Test
    void customToolWithUserProvidedShellBytes() {
        // TongWebExploit's Custom path: user supplies the shell class, server injects it
        MemShellResult godzilla = generate(ShellTool.Godzilla, ShellType.FILTER, defaultParams());
        String shellClassBase64 = Base64.getEncoder().encodeToString(godzilla.getShellBytes());

        ShellConfig shellConfig = baseShellConfig(ShellTool.Custom, ShellType.FILTER);
        ShellToolConfig customConfig = CustomConfig.builder()
                .shellClassBase64(shellClassBase64)
                .build();
        MemShellResult result = new MemShellGenerator().generate(shellConfig, InjectorConfig.builder().build(), customConfig);

        assertResultContract(result);
    }

    @Test
    void injectorBase64IsPayloadReady() {
        // the payload builder embeds injectorBytesBase64Str into an EL expression;
        // it must be a faithful Base64 encoding of injectorBytes
        MemShellResult result = generate(ShellTool.Godzilla, ShellType.FILTER, defaultParams());
        byte[] decoded = Base64.getDecoder().decode(result.getInjectorBytesBase64Str());
        assertArrayEquals(result.getInjectorBytes(), decoded);
    }

    private static MemShellResult generate(String shellTool, String shellType, Map<String, String> params) {
        ShellConfig shellConfig = baseShellConfig(shellTool, shellType);
        InjectorConfig injectorConfig = InjectorConfig.builder()
                .urlPattern("/*")
                .staticInitialize(false)
                .build();
        return new MemShellGenerator().generate(shellConfig, injectorConfig, params);
    }

    private static ShellConfig baseShellConfig(String shellTool, String shellType) {
        return ShellConfig.builder()
                .server(Server.TongWeb)
                .serverVersion("7")
                .shellTool(shellTool)
                .shellType(shellType)
                .shrink(true)
                .debug(false)
                .probe(false)
                .lambdaSuffix(false)
                .jakarta(false)
                .byPassJavaModule(false)
                .build();
    }

    private static Map<String, String> defaultParams() {
        Map<String, String> params = new HashMap<>();
        params.put("pass", "pass");
        params.put("key", "key");
        return params;
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
