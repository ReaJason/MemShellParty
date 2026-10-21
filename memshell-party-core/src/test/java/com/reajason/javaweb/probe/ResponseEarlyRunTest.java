package com.reajason.javaweb.probe;

import com.reajason.javaweb.Server;
import com.reajason.javaweb.probe.config.ProbeConfig;
import com.reajason.javaweb.probe.config.ResponseConfig;
import com.reajason.javaweb.probe.generator.response.ResponseGenerator;
import com.reajason.javaweb.probe.payload.EarlyRunFixture;
import com.reajason.javaweb.utils.Base64Utils;
import com.reajason.javaweb.utils.CommonUtil;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.io.PrintWriter;
import java.lang.reflect.InvocationHandler;
import java.lang.reflect.Method;
import java.lang.reflect.Proxy;
import java.util.HashMap;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;

/**
 * 回显马「先执行再回显」（issue #123）：固定数据模式（内置字节码）不依赖请求对象，
 * 即使回显位置定位失败字节码也必须已经执行；参数触发模式维持原有「先定位再执行」。
 * <p>
 * 内嵌字节码用 {@link EarlyRunFixture}：构造时写 System property（JVM 级标记，
 * 无回显也能观测），toString 返回固定串供回显断言。
 */
class ResponseEarlyRunTest {

    private ByteArrayOutputStream body;
    private ThreadLocal<Object> requestHolder;

    @BeforeEach
    void clearMarker() {
        System.clearProperty(EarlyRunFixture.MARKER_KEY);
    }

    /**
     * 每个 Response writer 在「没有容器运行环境」的 JVM 里实例化时回显定位必然失败，
     * 内置字节码也必须先执行 —— issue #123 的核心诉求。
     * UnknownWriter 除外：它的 BFS 会遍历测试 JVM 对象图，慢且与容器 writer 路径无关，
     * 其执行顺序由下面两个 Unknown 用例覆盖。
     */
    @Test
    void fixedBytecodeRunsEvenWhenEchoLookupFails() throws Exception {
        for (String server : ResponseGenerator.getSupportedServers()) {
            if (Server.Unknown.equals(server)) {
                continue;
            }
            try {
                ProbeShellResult result = generateFixedBytecodeProbe(server,
                        "com.example.EarlyRun" + server);
                instantiate(result);
                assertEquals(EarlyRunFixture.MARKER_VALUE, System.getProperty(EarlyRunFixture.MARKER_KEY),
                        server + " 回显定位失败时内置字节码也应已执行");
            } finally {
                System.clearProperty(EarlyRunFixture.MARKER_KEY);
            }
        }
    }

    /**
     * 固定字节码 + 能定位到当前请求：先执行的结果经缓存写入响应，不重复执行
     */
    @Test
    void fixedBytecodeRunsAndEchoesWhenRequestLocated() throws Exception {
        installFakeRequest(null, null);
        ProbeShellResult result = generateFixedBytecodeProbe(Server.Unknown, "com.example.EarlyRunUnknownEcho");
        try {
            instantiate(result);
        } finally {
            requestHolder.remove();
        }
        assertEquals(EarlyRunFixture.MARKER_VALUE, System.getProperty(EarlyRunFixture.MARKER_KEY));
        assertEquals(EarlyRunFixture.ECHO_TEXT, body.toString());
    }

    /**
     * 参数触发模式回归：请求里没有触发参数时不得执行字节码，也不得有回显
     */
    @Test
    void paramTriggeredProbeDoesNotRunWithoutParam() throws Exception {
        installFakeRequest(null, null);
        ProbeShellResult result = generateParamBytecodeProbe("com.example.ParamProbeNoTrigger");
        try {
            instantiate(result);
        } finally {
            requestHolder.remove();
        }
        assertNull(System.getProperty(EarlyRunFixture.MARKER_KEY),
                "参数触发模式没有触发参数时不得执行字节码");
        assertEquals("", body.toString());
    }

    /**
     * 参数触发模式回归：携带触发参数时照旧「先定位再执行」并回显
     */
    @Test
    void paramTriggeredProbeStillRunsWithParam() throws Exception {
        installFakeRequest("payload", fixedBase64());
        ProbeShellResult result = generateParamBytecodeProbe("com.example.ParamProbeWithTrigger");
        try {
            instantiate(result);
        } finally {
            requestHolder.remove();
        }
        assertEquals(EarlyRunFixture.MARKER_VALUE, System.getProperty(EarlyRunFixture.MARKER_KEY));
        assertEquals(EarlyRunFixture.ECHO_TEXT, body.toString());
    }

    private static ProbeShellResult generateFixedBytecodeProbe(String server, String className) throws Exception {
        ProbeConfig probeConfig = ProbeConfig.builder()
                .probeMethod(ProbeMethod.ResponseBody)
                .probeContent(ProbeContent.Bytecode)
                .shellClassName(className)
                .build();
        ResponseConfig contentConfig = ResponseConfig.builder()
                .server(server)
                .base64Bytes(fixedBase64())
                .build();
        return ProbeShellGenerator.generate(probeConfig, contentConfig);
    }

    private static ProbeShellResult generateParamBytecodeProbe(String className) {
        ProbeConfig probeConfig = ProbeConfig.builder()
                .probeMethod(ProbeMethod.ResponseBody)
                .probeContent(ProbeContent.Bytecode)
                .shellClassName(className)
                .build();
        ResponseConfig contentConfig = ResponseConfig.builder()
                .server(Server.Unknown)
                .reqParamName("payload")
                .build();
        return ProbeShellGenerator.generate(probeConfig, contentConfig);
    }

    /**
     * 与 MemShellGenerator 回显模式一致的内嵌格式：gzip + base64（H4s 前缀触发 gunzip）
     */
    private static String fixedBase64() throws Exception {
        InputStream in = ResponseEarlyRunTest.class.getResourceAsStream(
                "/com/reajason/javaweb/probe/payload/EarlyRunFixture.class");
        assert in != null;
        byte[] bytes = readAll(in);
        in.close();
        return Base64Utils.encodeBase64String(CommonUtil.gzipCompress(bytes));
    }

    private static byte[] readAll(InputStream in) throws Exception {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        byte[] buffer = new byte[4096];
        int n;
        while ((n = in.read(buffer)) > 0) {
            out.write(buffer, 0, n);
        }
        return out.toByteArray();
    }

    private void installFakeRequest(String paramName, String paramValue) {
        body = new ByteArrayOutputStream();
        InvocationHandler responseHandler = (proxy, method, args) -> {
            switch (method.getName()) {
                case "getOutputStream":
                    return body;
                case "getWriter":
                    return new PrintWriter(body);
                case "isCommitted":
                    return false;
                default:
                    return objectMethod(proxy, method, args);
            }
        };
        Object response = Proxy.newProxyInstance(getClass().getClassLoader(),
                new Class<?>[]{javax.servlet.http.HttpServletResponse.class}, responseHandler);
        InvocationHandler requestHandler = (proxy, method, args) -> {
            switch (method.getName()) {
                case "getResponse":
                    return response;
                case "getParameter":
                case "getHeader":
                    return paramName != null && paramName.equals(args[0]) ? paramValue : null;
                default:
                    return objectMethod(proxy, method, args);
            }
        };
        Object request = Proxy.newProxyInstance(getClass().getClassLoader(),
                new Class<?>[]{javax.servlet.http.HttpServletRequest.class}, requestHandler);
        requestHolder = new ThreadLocal<>();
        requestHolder.set(request);
    }

    private static Object objectMethod(Object proxy, Method method, Object[] args) {
        switch (method.getName()) {
            case "hashCode":
                return System.identityHashCode(proxy);
            case "equals":
                return proxy == args[0];
            case "toString":
                return "fake-" + proxy.getClass().getInterfaces()[0].getSimpleName();
            default:
                return null;
        }
    }

    private void instantiate(ProbeShellResult result) throws Exception {
        byte[] bytes = result.getShellBytes();
        String className = result.getShellClassName();
        ClassLoader loader = new ClassLoader(getClass().getClassLoader()) {
        };
        Method define = ClassLoader.class.getDeclaredMethod(
                "defineClass", String.class, byte[].class, int.class, int.class);
        define.setAccessible(true);
        Class<?> clazz = (Class<?>) define.invoke(loader, className, bytes, 0, bytes.length);
        clazz.newInstance();
    }
}
