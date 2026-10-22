package com.reajason.javaweb.examples.customgui.shelltool;

import com.reajason.javaweb.GenerationException;
import com.reajason.javaweb.Server;
import com.reajason.javaweb.memshell.MemShellGenerator;
import com.reajason.javaweb.memshell.MemShellRegistry;
import com.reajason.javaweb.memshell.MemShellResult;
import com.reajason.javaweb.memshell.config.InjectorConfig;
import com.reajason.javaweb.memshell.config.ShellConfig;
import com.reajason.javaweb.memshell.server.AbstractServer;
import com.reajason.javaweb.utils.ClassDefiner;
import com.reajason.javaweb.utils.DigestUtils;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import java.lang.reflect.Field;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Stream;

import static com.reajason.javaweb.memshell.ShellType.*;
import static org.junit.jupiter.api.Assertions.*;

/**
 * 生成期验证：自定义 shelltool 通过 SPI 注册、只暴露 servlet-api 相关的 shellType、
 * 生成出的类带齐字段且不含 payload 静态字段。
 *
 * @author ReaJason
 */
class GodzillaSessionShellToolProviderTest {

    private static final String TOOL = GodzillaSessionShellToolProvider.NAME;

    static Stream<Arguments> servletApiShellTypes() {
        return Stream.of(
                Arguments.of(FILTER),
                Arguments.of(JAKARTA_FILTER),
                Arguments.of(SERVLET),
                Arguments.of(JAKARTA_SERVLET),
                Arguments.of(LISTENER),
                Arguments.of(JAKARTA_LISTENER));
    }

    @Test
    void spiDiscoversTheCustomTool() {
        // 依赖 META-INF/services 里的注册（@MetaInfServices 生成），合并 SPI 文件后使用方才能看到它
        assertTrue(MemShellRegistry.getInstance().getSupportedTools().contains(TOOL),
                TOOL + " not registered: " + MemShellRegistry.getInstance().getSupportedTools());
        assertSame(GodzillaSessionConfig.class, MemShellRegistry.getInstance().getToolProvider(TOOL).getConfigClass());
        assertSame(GodzillaSessionGenerator.class, MemShellRegistry.getInstance().getToolProvider(TOOL).getGeneratorClass());
    }

    @Test
    void onlyServletApiShellTypesAreAdvertised() {
        AbstractServer tomcat = MemShellRegistry.getInstance().getServer(Server.Tomcat);
        Set<String> supported = tomcat.getSupportedShellTypes(TOOL);
        assertEquals(6, supported.size(), "unexpected shell types: " + supported);
        List<String> expected = Arrays.asList(FILTER, JAKARTA_FILTER, SERVLET, JAKARTA_SERVLET, LISTENER, JAKARTA_LISTENER);
        assertTrue(supported.containsAll(expected), supported.toString());
        // 模板里没实现的类型不会被广告出来（registry 会和 server 的注入器映射求交集）
        assertFalse(supported.contains(VALVE), supported.toString());
    }

    @ParameterizedTest
    @MethodSource("servletApiShellTypes")
    void generatesShellWithoutPayloadStaticField(String shellType) {
        GodzillaSessionConfig toolConfig = GodzillaSessionConfig.builder()
                .pass("passFilter")
                .key("keyFilter")
                .headerName("User-Agent")
                .headerValue("Firefox")
                .sessionKey("sessionCore")
                .build();

        MemShellResult result = generate(shellType, toolConfig);

        assertEquals("sessionCore", toolConfig.getSessionKey());
        assertTrue(result.getShellBytes().length > 0);
        assertEquals(result.getShellBytes().length, result.getShellSize());

        Class<?> shellClass = ClassDefiner.defineClass(result.getShellBytes());
        assertEquals(toolConfig.getShellClassName(), shellClass.getName());
        // 协议字段照旧，只是多了 core 在会话里的 key
        assertEquals("passFilter", readStaticField(shellClass, "pass"));
        assertEquals(DigestUtils.md5Hex("keyFilter").substring(0, 16), readStaticField(shellClass, "key"));
        assertEquals("User-Agent", readStaticField(shellClass, "headerName"));
        assertEquals("Firefox", readStaticField(shellClass, "headerValue"));
        assertEquals("sessionCore", readStaticField(shellClass, "sessionKey"));
        // 本示例的重点：core 不再常驻内存马类的静态字段
        assertThrows(NoSuchFieldException.class, () -> shellClass.getDeclaredField("payload"));
    }

    @ParameterizedTest
    @MethodSource("servletApiShellTypes")
    void generatesForOtherServletContainers(String shellType) {
        // 模板只依赖 servlet-api，换容器只是换 server（注入器由对应 server 模块提供）
        MemShellResult result = new MemShellGenerator().generate(
                ShellConfig.builder()
                        .server(Server.Undertow)
                        .shellTool(TOOL)
                        .shellType(shellType)
                        .build(),
                InjectorConfig.builder().urlPattern("/*").build(),
                GodzillaSessionConfig.builder().build());
        assertTrue(result.getShellBytes().length > 0);
        assertTrue(result.getInjectorBytes().length > 0);
        assertEquals(TOOL, result.getShellConfig().getShellTool());
    }

    @Test
    void jakartaShellTypeUsesJakartaServletApi() {
        MemShellResult result = generate(JAKARTA_FILTER, GodzillaSessionConfig.builder().build());
        String constantPool = new String(result.getShellBytes(), StandardCharsets.ISO_8859_1);
        assertTrue(constantPool.contains("jakarta/servlet/http/HttpSession"), "not relocated to jakarta");
        assertFalse(constantPool.contains("javax/servlet/"), "javax.servlet leaked into jakarta shell");
    }

    @Test
    void dynamicParamsBindToTheCustomConfig() {
        // GUI / REST / MCP 走的就是这条路径：先 build 出带随机默认值的配置，再按 @ConfigField
        // 字段写入字符串参数；参数名就是字段名，不带工具名前缀
        Map<String, String> params = new HashMap<>();
        params.put("pass", "passFilter");
        params.put("key", "keyFilter");
        params.put("sessionKey", "sessionCore");

        MemShellResult result = new MemShellGenerator().generate(
                shellConfig(FILTER), InjectorConfig.builder().urlPattern("/*").build(), params);

        GodzillaSessionConfig built = (GodzillaSessionConfig) result.getShellToolConfig();
        assertEquals("passFilter", built.getPass());
        assertEquals("keyFilter", built.getKey());
        assertEquals("sessionCore", built.getSessionKey());
        assertNotNull(built.getHeaderValue(), "未传的参数保持随机默认值");
        assertEquals(built.getSessionKey(), readStaticField(ClassDefiner.defineClass(result.getShellBytes()), "sessionKey"));
    }

    @Test
    void unknownParamIsRejected() {
        // 拼错的参数名不能静默吞掉：否则表单里填的值不会生效，用户却以为生效了
        Map<String, String> params = new HashMap<>();
        params.put("pass", "passFilter");
        params.put("godzillaSessionPass", "prefixIsNoLongerStripped");

        GenerationException exception = assertThrows(GenerationException.class, () -> new MemShellGenerator().generate(
                shellConfig(FILTER), InjectorConfig.builder().urlPattern("/*").build(), params));
        assertTrue(exception.getMessage().contains("godzillaSessionPass"), exception.getMessage());
        assertTrue(exception.getMessage().contains("pass"), exception.getMessage());
    }

    private static MemShellResult generate(String shellType, GodzillaSessionConfig toolConfig) {
        return new MemShellGenerator().generate(shellConfig(shellType), InjectorConfig.builder().urlPattern("/*").build(), toolConfig);
    }

    private static ShellConfig shellConfig(String shellType) {
        return ShellConfig.builder()
                .server(Server.Tomcat)
                .shellTool(TOOL)
                .shellType(shellType)
                .build();
    }

    private static String readStaticField(Class<?> clazz, String name) {
        try {
            Field field = clazz.getDeclaredField(name);
            field.setAccessible(true);
            return (String) field.get(null);
        } catch (ReflectiveOperationException e) {
            throw new AssertionError(e);
        }
    }
}
