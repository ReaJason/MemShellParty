package com.reajason.javaweb.memshell.shelltool.godzilla.session;

import com.reajason.javaweb.GenerationException;
import com.reajason.javaweb.Server;
import com.reajason.javaweb.memshell.MemShellGenerator;
import com.reajason.javaweb.memshell.MemShellRegistry;
import com.reajason.javaweb.memshell.MemShellResult;
import com.reajason.javaweb.memshell.ShellTool;
import com.reajason.javaweb.memshell.config.InjectorConfig;
import com.reajason.javaweb.memshell.config.ShellConfig;
import com.reajason.javaweb.memshell.server.AbstractServer;
import com.reajason.javaweb.memshell.shelltool.godzilla.GodzillaConfig;
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
 * 生成期验证：GodzillaSession 通过 SPI 注册、只暴露能拿到 HttpSession 的 shellType、
 * 生成出的类带齐哥斯拉协议字段且不含 payload 静态字段。
 *
 * @author ReaJason
 */
class GodzillaSessionShellToolProviderTest {

    private static final String TOOL = ShellTool.GodzillaSession;

    static Stream<Arguments> sessionShellTypes() {
        return Stream.of(
                Arguments.of(FILTER),
                Arguments.of(JAKARTA_FILTER),
                Arguments.of(SERVLET),
                Arguments.of(JAKARTA_SERVLET),
                Arguments.of(LISTENER),
                Arguments.of(JAKARTA_LISTENER),
                Arguments.of(VALVE),
                Arguments.of(PROXY_VALVE),
                Arguments.of(JAKARTA_PROXY_VALVE),
                Arguments.of(AGENT_FILTER_CHAIN),
                Arguments.of(CATALINA_AGENT_CONTEXT_VALVE));
    }

    @Test
    void spiDiscoversTheTool() {
        assertTrue(MemShellRegistry.getInstance().getSupportedTools().contains(TOOL),
                TOOL + " not registered: " + MemShellRegistry.getInstance().getSupportedTools());
        assertSame(GodzillaConfig.class, MemShellRegistry.getInstance().getToolProvider(TOOL).getConfigClass());
        assertSame(GodzillaSessionGenerator.class, MemShellRegistry.getInstance().getToolProvider(TOOL).getGeneratorClass());
    }

    @Test
    void onlySessionCapableShellTypesAreAdvertised() {
        AbstractServer tomcat = MemShellRegistry.getInstance().getServer(Server.Tomcat);
        Set<String> supported = tomcat.getSupportedShellTypes(TOOL);
        List<String> expected = Arrays.asList(FILTER, JAKARTA_FILTER, SERVLET, JAKARTA_SERVLET,
                LISTENER, JAKARTA_LISTENER, VALVE, JAKARTA_VALVE,
                PROXY_VALVE, JAKARTA_PROXY_VALVE, AGENT_FILTER_CHAIN, CATALINA_AGENT_CONTEXT_VALVE);
        assertEquals(expected.size(), supported.size(), "unexpected shell types: " + supported);
        assertTrue(supported.containsAll(expected), supported.toString());
        // 拿不到 HttpSession 的类型不会被广告出来（registry 会和 server 的注入器映射求交集）
        assertFalse(supported.contains(WEBSOCKET), supported.toString());
    }

    @ParameterizedTest
    @MethodSource("sessionShellTypes")
    void generatesShellWithoutPayloadStaticField(String shellType) {
        GodzillaConfig toolConfig = GodzillaConfig.builder()
                .pass("passFilter")
                .key("keyFilter")
                .headerName("User-Agent")
                .headerValue("Firefox")
                .build();

        MemShellResult result = generate(shellType, toolConfig);

        assertTrue(result.getShellBytes().length > 0);
        assertEquals(result.getShellBytes().length, result.getShellSize());

        Class<?> shellClass = ClassDefiner.defineClass(result.getShellBytes());
        assertEquals(result.getShellClassName(), shellClass.getName());
        // 协议字段与哥斯拉一致，多出来的只有会话属性名 sessionKey
        assertEquals("passFilter", readStaticField(shellClass, "pass"));
        assertEquals(DigestUtils.md5Hex("keyFilter").substring(0, 16), readStaticField(shellClass, "key"));
        assertEquals("User-Agent", readStaticField(shellClass, "headerName"));
        assertEquals("Firefox", readStaticField(shellClass, "headerValue"));
        String sessionKey = readStaticField(shellClass, "sessionKey");
        assertNotNull(sessionKey);
        assertFalse(sessionKey.isEmpty(), "sessionKey 应由生成器随机填充");
        // 本工具的重点：core 不再常驻内存马类的静态字段
        assertThrows(NoSuchFieldException.class, () -> shellClass.getDeclaredField("payload"));
        // 拿不到会话的场景（如 engine/host 级 Valve、包装请求）要给用户能看懂的报错，而不是 NPE
        assertTrue(new String(result.getShellBytes(), StandardCharsets.ISO_8859_1).contains("session is null"),
                "缺少 session 为空的显式报错");
    }

    @Test
    void sessionKeyIsRandomPerGeneration() {
        GodzillaConfig toolConfig = GodzillaConfig.builder().pass("passFilter").key("keyFilter").build();
        String first = readStaticField(ClassDefiner.defineClass(generate(FILTER, toolConfig).getShellBytes()), "sessionKey");
        String second = readStaticField(ClassDefiner.defineClass(generate(FILTER, toolConfig).getShellBytes()), "sessionKey");
        assertNotEquals(first, second, "同一份配置生成两次，sessionKey 不应相同，否则同会话内会读到同一个 core");
    }

    @Test
    void jakartaShellTypeUsesJakartaServletApi() {
        MemShellResult result = generate(JAKARTA_FILTER, GodzillaConfig.builder().build());
        String constantPool = new String(result.getShellBytes(), StandardCharsets.ISO_8859_1);
        assertTrue(constantPool.contains("jakarta/servlet/http/HttpSession"), "not relocated to jakarta");
        assertFalse(constantPool.contains("javax/servlet/"), "javax.servlet leaked into jakarta shell");
    }

    @Test
    void dynamicParamsBindToGodzillaConfig() {
        // GUI / REST / MCP 走的就是这条路径：参数名与 GodzillaConfig 的 @ConfigField 字段一致
        Map<String, String> params = new HashMap<>();
        params.put("pass", "passFilter");
        params.put("key", "keyFilter");

        MemShellResult result = new MemShellGenerator().generate(
                shellConfig(FILTER), InjectorConfig.builder().urlPattern("/*").build(), params);

        GodzillaConfig built = (GodzillaConfig) result.getShellToolConfig();
        assertEquals("passFilter", built.getPass());
        assertEquals("keyFilter", built.getKey());
        assertNotNull(built.getHeaderValue(), "未传的参数保持随机默认值");
    }

    @Test
    void unknownParamIsRejected() {
        // 拼错的参数名不能静默吞掉：否则表单里填的值不会生效，用户却以为生效了
        Map<String, String> params = new HashMap<>();
        params.put("pass", "passFilter");
        params.put("sessionKey", "notAConfigField");

        GenerationException exception = assertThrows(GenerationException.class, () -> new MemShellGenerator().generate(
                shellConfig(FILTER), InjectorConfig.builder().urlPattern("/*").build(), params));
        assertTrue(exception.getMessage().contains("sessionKey"), exception.getMessage());
        assertTrue(exception.getMessage().contains("pass"), exception.getMessage());
    }

    private static MemShellResult generate(String shellType, GodzillaConfig toolConfig) {
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
