package com.reajason.javaweb.memshell.generator.processors;

import com.reajason.javaweb.GenerationException;
import com.reajason.javaweb.asm.ClassRenameUtils;
import com.reajason.javaweb.asm.ClassSuperClassUtils;
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
                        bytes = ClassRenameUtils.relocateClass(bytes, "org/eclipse/jetty/server", "org/mortbay/jetty");
                        break;
                    case "7+":
                        superClassName = "org/eclipse/jetty/server/handler/AbstractHandler";
                        break;
                    case "12":
                        superClassName = "org/eclipse/jetty/server/Handler$Abstract";
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
