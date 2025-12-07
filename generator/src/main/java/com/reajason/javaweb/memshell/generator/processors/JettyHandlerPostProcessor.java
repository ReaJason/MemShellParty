package com.reajason.javaweb.memshell.generator.processors;

import com.reajason.javaweb.GenerationException;
import com.reajason.javaweb.asm.ClassRenameUtils;
import com.reajason.javaweb.asm.ClassSuperClassUtils;
import com.reajason.javaweb.asm.MethodUtils;
import com.reajason.javaweb.memshell.ServerFactory;
import com.reajason.javaweb.memshell.ShellType;
import com.reajason.javaweb.memshell.config.ShellConfig;
import com.reajason.javaweb.memshell.config.ShellToolConfig;
import com.reajason.javaweb.memshell.generator.Processor;
import com.reajason.javaweb.memshell.server.AbstractServer;
import com.reajason.javaweb.memshell.server.Jetty;

/**
 * @author ReaJason
 * @since 2025/12/7
 */
public class JettyHandlerPostProcessor implements Processor<byte[]> {

    @Override
    public byte[] process(byte[] bytes, ShellConfig shellConfig, ShellToolConfig shellToolConfig) {
        AbstractServer server = ServerFactory.getServer(shellConfig.getServer());
        String shellType = shellConfig.getShellType();
        if (server instanceof Jetty
                && (ShellType.HANDLER.equals(shellType)
                || ShellType.JAKARTA_HANDLER.equals(shellType))
        ) {
            String superClassName = null;
            String serverVersion = shellConfig.getServerVersion();
            if (serverVersion != null) {
                switch (serverVersion) {
                    case "6":
                        superClassName = "org/mortbay/jetty/handler/AbstractHandler";
                        bytes = MethodUtils.removeMethodByMethodDescriptor(bytes, "handle", "(Lorg/eclipse/jetty/server/Request;Lorg/eclipse/jetty/server/Response;Lorg/eclipse/jetty/util/Callback;)Z");
                        bytes = MethodUtils.removeMethodByMethodDescriptor(bytes, "handle", "(Ljava/lang/String;Lorg/eclipse/jetty/server/Request;Ljavax/servlet/http/HttpServletRequest;Ljavax/servlet/http/HttpServletResponse;)V");
                        bytes = ClassRenameUtils.relocateClass(bytes, "org/eclipse/jetty/server", "org/mortbay/jetty");
                        break;
                    case "7+":
                        superClassName = "org/eclipse/jetty/server/handler/AbstractHandler";
                        bytes = MethodUtils.removeMethodByMethodDescriptor(bytes, "handle", "(Lorg/eclipse/jetty/server/Request;Lorg/eclipse/jetty/server/Response;Lorg/eclipse/jetty/util/Callback;)Z");
                        bytes = MethodUtils.removeMethodByMethodDescriptor(bytes, "handle", "(Ljava/lang/String;Ljavax/servlet/http/HttpServletRequest;Ljavax/servlet/http/HttpServletResponse;I)V");
                        bytes = MethodUtils.removeMethodByMethodDescriptor(bytes, "handle", "(Ljava/lang/String;Ljakarta/servlet/http/HttpServletRequest;Ljakarta/servlet/http/HttpServletResponse;I)V");
                        break;
                    case "12":
                        superClassName = "org/eclipse/jetty/server/Handler$Abstract";
                        bytes = MethodUtils.removeMethodByMethodDescriptor(bytes, "handle", "(Ljava/lang/Object;Ljava/lang/Object;)Z");
                        bytes = MethodUtils.removeMethodByMethodDescriptor(bytes, "handle", "(Ljava/lang/String;Ljavax/servlet/http/HttpServletRequest;Ljavax/servlet/http/HttpServletResponse;I)V");
                        bytes = MethodUtils.removeMethodByMethodDescriptor(bytes, "handle", "(Ljava/lang/String;Ljakarta/servlet/http/HttpServletRequest;Ljakarta/servlet/http/HttpServletResponse;I)V");
                        bytes = MethodUtils.removeMethodByMethodDescriptor(bytes, "handle", "(Ljava/lang/String;Lorg/eclipse/jetty/server/Request;Ljavax/servlet/http/HttpServletRequest;Ljavax/servlet/http/HttpServletResponse;)V");
                        bytes = MethodUtils.removeMethodByMethodDescriptor(bytes, "handle", "(Ljava/lang/String;Lorg/eclipse/jetty/server/Request;Ljakarta/servlet/http/HttpServletRequest;Ljakarta/servlet/http/HttpServletResponse;)V");
                        break;
                }
            }
            if (superClassName == null) {
                throw new GenerationException("serverVersion is needed for Jetty Handler or unknow serverVersion: [" + serverVersion + "], please use one of ['6', '7+', '12'] for shellConfig.serverVersion");
            }
            return ClassSuperClassUtils.addSuperClass(bytes, superClassName);
        }
        return bytes;
    }
}
