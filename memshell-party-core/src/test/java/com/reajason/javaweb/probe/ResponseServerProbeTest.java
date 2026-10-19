package com.reajason.javaweb.probe;

import com.reajason.javaweb.Server;
import com.reajason.javaweb.probe.config.ProbeConfig;
import com.reajason.javaweb.probe.config.ResponseConfig;
import com.reajason.javaweb.probe.generator.response.ResponseGenerator;
import org.junit.jupiter.api.Test;
import org.objectweb.asm.ClassReader;

import java.io.ByteArrayOutputStream;
import java.io.PrintWriter;
import java.lang.reflect.InvocationHandler;
import java.lang.reflect.Proxy;
import java.util.HashMap;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

/**
 * ResponseBody/ResponseHeader 的 Server 探测内容与 Unknown 中间件 writer。
 * UnknownWriter 的 BFS 用 javax.servlet 桩接口 + 动态代理模拟一次真实请求，
 * request 对象通过 ThreadLocal 挂在当前线程上，等价于 BFS 在容器里的定位路径。
 */
class ResponseServerProbeTest {

    private ByteArrayOutputStream body;
    private Map<String, String> headers;
    private ThreadLocal<Object> requestHolder;

    private void installFakeRequest(String paramName, String paramValue) {
        body = new ByteArrayOutputStream();
        headers = new HashMap<>();
        InvocationHandler responseHandler = (proxy, method, args) -> {
            switch (method.getName()) {
                case "getOutputStream":
                    return body;
                case "getWriter":
                    return new PrintWriter(body);
                case "setHeader":
                    headers.put((String) args[0], (String) args[1]);
                    return null;
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

    /**
     * proxy 的 hashCode/equals/toString 也会走 InvocationHandler，DFS 的 visited 集合依赖 hashCode，
     * 不处理会拆箱 NPE 导致遍历分支被放弃
     */
    private static Object objectMethod(Object proxy, java.lang.reflect.Method method, Object[] args) {
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
        java.lang.reflect.Method define = ClassLoader.class.getDeclaredMethod(
                "defineClass", String.class, byte[].class, int.class, int.class);
        define.setAccessible(true);
        Class<?> clazz = (Class<?>) define.invoke(loader, className, bytes, 0, bytes.length);
        clazz.newInstance();
    }

    @Test
    void serverContentShouldEchoDetectedTypeThroughUnknownWriter() throws Exception {
        // Unknown 中间件的 Server 探测也走触发参数：BFS 靠参数认出当前请求，
        // 避免命中对象图里残留的已回收请求对象
        installFakeRequest("serverType", "1");
        ProbeConfig probeConfig = ProbeConfig.builder()
                .probeMethod(ProbeMethod.ResponseBody)
                .probeContent(ProbeContent.Server)
                .debug(true)
                .shellClassName("com.example.UnknownServerBodyProbe")
                .build();
        ResponseConfig contentConfig = ResponseConfig.builder()
                .server(Server.Unknown)
                .reqParamName("serverType")
                .build();
        ProbeShellResult result = ProbeShellGenerator.generate(probeConfig, contentConfig);
        try {
            instantiate(result);
        } finally {
            requestHolder.remove();
        }
        // 测试 JVM 里没有任何容器特征，探测结果即 Unknown
        assertEquals("Unknown", body.toString());
    }

    @Test
    void serverContentShouldEchoDetectedTypeThroughUnknownWriterHeader() throws Exception {
        installFakeRequest("serverType", "1");
        ProbeConfig probeConfig = ProbeConfig.builder()
                .probeMethod(ProbeMethod.ResponseHeader)
                .probeContent(ProbeContent.Server)
                .debug(true)
                .shellClassName("com.example.UnknownServerHeaderProbe")
                .build();
        ResponseConfig contentConfig = ResponseConfig.builder()
                .server(Server.Unknown)
                .reqParamName("serverType")
                .build();
        ProbeShellResult result = ProbeShellGenerator.generate(probeConfig, contentConfig);
        try {
            instantiate(result);
        } finally {
            requestHolder.remove();
        }
        String headerName = contentConfig.getRespHeaderName();
        assertNotNull(headerName, "生成器应回写随机响应头名");
        assertEquals("Unknown", headers.get(headerName));
        assertEquals("", body.toString(), "ResponseHeader 不允许回落到响应体");
    }

    @Test
    void commandContentShouldEchoCommandOutputThroughUnknownWriter() throws Exception {
        installFakeRequest("cmd", "echo memparty-dfs");
        ProbeConfig probeConfig = ProbeConfig.builder()
                .probeMethod(ProbeMethod.ResponseBody)
                .probeContent(ProbeContent.Command)
                .debug(true)
                .shellClassName("com.example.UnknownCommandProbe")
                .build();
        ResponseConfig contentConfig = ResponseConfig.builder()
                .server(Server.Unknown)
                .reqParamName("cmd")
                .build();
        ProbeShellResult result = ProbeShellGenerator.generate(probeConfig, contentConfig);
        try {
            instantiate(result);
        } finally {
            requestHolder.remove();
        }
        assertTrue(body.toString().contains("memparty-dfs"), "body: " + body);
    }

    @Test
    void serverContentShouldGenerateForEverySupportedServer() {
        for (String server : ResponseGenerator.getSupportedServers()) {
            for (ProbeMethod method : new ProbeMethod[]{ProbeMethod.ResponseBody, ProbeMethod.ResponseHeader}) {
                ProbeConfig probeConfig = ProbeConfig.builder()
                        .probeMethod(method)
                        .probeContent(ProbeContent.Server)
                        .shellClassName("com.example.ServerProbe" + server + method.name())
                        .build();
                ResponseConfig contentConfig = ResponseConfig.builder().server(server).build();
                ProbeShellResult result = ProbeShellGenerator.generate(probeConfig, contentConfig);
                assertEquals("com.example.ServerProbe" + server + method.name(),
                        new ClassReader(result.getShellBytes()).getClassName().replace('/', '.'));
            }
        }
    }
}
