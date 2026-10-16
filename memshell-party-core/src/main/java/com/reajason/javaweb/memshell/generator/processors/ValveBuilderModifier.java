package com.reajason.javaweb.memshell.generator.processors;

import com.reajason.javaweb.GenerationException;
import com.reajason.javaweb.Server;
import com.reajason.javaweb.memshell.MemShellRegistry;
import com.reajason.javaweb.memshell.ShellType;
import com.reajason.javaweb.memshell.config.ShellConfig;
import com.reajason.javaweb.memshell.config.ShellToolConfig;
import com.reajason.javaweb.memshell.generator.Processor;
import com.reajason.javaweb.memshell.server.AbstractServer;
import com.reajason.javaweb.utils.StringUtils;
import net.bytebuddy.asm.AsmVisitorWrapper;
import net.bytebuddy.description.field.FieldDescription;
import net.bytebuddy.description.field.FieldList;
import net.bytebuddy.description.method.MethodList;
import net.bytebuddy.description.type.TypeDescription;
import net.bytebuddy.dynamic.DynamicType;
import net.bytebuddy.implementation.Implementation;
import net.bytebuddy.jar.asm.ClassVisitor;
import net.bytebuddy.jar.asm.Opcodes;
import net.bytebuddy.jar.asm.commons.ClassRemapper;
import net.bytebuddy.jar.asm.commons.Remapper;
import net.bytebuddy.pool.TypePool;

/**
 * @author ReaJason
 * @since 2025/12/7
 */
public class ValveBuilderModifier implements Processor<DynamicType.Builder<?>> {

    @Override
    public DynamicType.Builder<?> process(DynamicType.Builder<?> builder, ShellConfig shellConfig, ShellToolConfig shellToolConfig) {
        String shellType = shellConfig.getShellType();
        AbstractServer server = MemShellRegistry.getInstance().getServer(shellConfig.getServer());
        if (ShellType.VALVE.equals(shellType) || ShellType.JAKARTA_VALVE.equals(shellType)) {
            builder = modifier(builder, server, shellConfig);
        }
        return builder;
    }

    public static final String CATALINA_VALVE_PACKAGE = "org.apache.catalina";
    public static final String BES_VALVE_PACKAGE = "com.bes.enterprise.webtier";
    public static final String TONGWEB6_VALVE_PACKAGE = "com.tongweb.web.thor";
    public static final String TONGWEB7_VALVE_PACKAGE = "com.tongweb.catalina";
    public static final String TONGWEB8_VALVE_PACKAGE = "com.tongweb.server";
    public static final String TONGWEB_EMBEDDED_VALVE_PACKAGE = "com.tongweb.container";

    public static DynamicType.Builder<?> modifier(DynamicType.Builder<?> builder, AbstractServer shell, ShellConfig shellConfig) {
        String packageName = null;
        String serverName = shellConfig.getServer();
        String serverVersion = shellConfig.getServerVersion();
        if (Server.BES.equals(serverName) || (shell != null && "Bes".equals(shell.getClass().getSimpleName()))) {
            packageName = BES_VALVE_PACKAGE;
        }
        if (Server.TongWeb.equals(serverName) || (shell != null && "TongWeb".equals(shell.getClass().getSimpleName()))) {
            // serverVersion 已由生成入口补齐（缺省 "unknown"），这里只认这几个版本，其余走 default 报错
            switch (serverVersion) {
                case "6":
                    packageName = TONGWEB6_VALVE_PACKAGE;
                    break;
                case "7":
                    packageName = TONGWEB7_VALVE_PACKAGE;
                    break;
                case "8":
                    packageName = TONGWEB8_VALVE_PACKAGE;
                    break;
                case "7.E":
                    packageName = TONGWEB_EMBEDDED_VALVE_PACKAGE;
                    break;
                default:
                    throw new GenerationException("TongWeb Valve unknow serverVersion: [" + serverVersion + "], please use one of ['6', '7', '8', '7.E'] for shellConfig.serverVersion");
            }
        }
        if (StringUtils.isNotBlank(packageName)) {
            return builder.visit(new ValveRenameVisitorWrapper(packageName));
        }
        return builder;
    }

    public static class ValveRenameVisitorWrapper implements AsmVisitorWrapper {
        private final String newPackageName;

        public ValveRenameVisitorWrapper(String newPackageName) {
            this.newPackageName = newPackageName.replace('.', '/');
        }

        @Override
        public int mergeReader(int flags) {
            return flags;
        }

        @Override
        public int mergeWriter(int flags) {
            return flags;
        }

        @Override
        public ClassVisitor wrap(TypeDescription instrumentedType,
                                 ClassVisitor classVisitor,
                                 Implementation.Context implementationContext,
                                 TypePool typePool,
                                 FieldList<FieldDescription.InDefinedShape> fields,
                                 MethodList<?> methods,
                                 int writerFlags,
                                 int readerFlags) {
            return new ClassRemapper(
                    classVisitor,
                    new Remapper(Opcodes.ASM9) {
                        @Override
                        public String map(String typeName) {
                            String packageName = CATALINA_VALVE_PACKAGE.replace(".", "/");
                            if (typeName.startsWith(packageName)) {
                                return typeName.replace(packageName, newPackageName);
                            } else {
                                return typeName;
                            }
                        }
                    });
        }
    }
}
