package com.reajason.javaweb.memshell.generator.processors;

import com.reajason.javaweb.GenerationException;
import com.reajason.javaweb.memshell.ServerFactory;
import com.reajason.javaweb.memshell.ShellType;
import com.reajason.javaweb.memshell.config.ShellConfig;
import com.reajason.javaweb.memshell.config.ShellToolConfig;
import com.reajason.javaweb.memshell.generator.Processor;
import com.reajason.javaweb.memshell.server.AbstractServer;
import com.reajason.javaweb.memshell.server.Bes;
import com.reajason.javaweb.memshell.server.TongWeb;
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
import org.apache.commons.lang3.StringUtils;
import org.jetbrains.annotations.NotNull;

/**
 * @author ReaJason
 * @since 2025/12/7
 */
public class ValveBuilderModifier implements Processor<DynamicType.Builder<?>> {

    @Override
    public DynamicType.Builder<?> process(DynamicType.Builder<?> builder, ShellConfig shellConfig, ShellToolConfig shellToolConfig) {
        String shellType = shellConfig.getShellType();
        AbstractServer server = ServerFactory.getServer(shellConfig.getServer());
        if (ShellType.VALVE.equals(shellType) || ShellType.JAKARTA_VALVE.equals(shellType)) {
            builder = modifier(builder, server, shellConfig.getServerVersion());
        }
        return builder;
    }

    public static final String CATALINA_VALVE_PACKAGE = "org.apache.catalina";
    public static final String BES_VALVE_PACKAGE = "com.bes.enterprise.webtier";
    public static final String TONGWEB6_VALVE_PACKAGE = "com.tongweb.web.thor";
    public static final String TONGWEB7_VALVE_PACKAGE = "com.tongweb.catalina";
    public static final String TONGWEB8_VALVE_PACKAGE = "com.tongweb.server";

    public static DynamicType.Builder<?> modifier(DynamicType.Builder<?> builder, AbstractServer shell, String serverVersion) {
        String packageName = null;
        if (shell instanceof Bes) {
            packageName = BES_VALVE_PACKAGE;
        }
        if (shell instanceof TongWeb) {
            if (serverVersion == null) {
                throw new GenerationException("serverVersion is needed for TongWeb Valve, please use one of ['6', '7', '8'] for shellConfig.serverVersion");
            }
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
                default:
                    throw new GenerationException("TongWeb Valve unknow serverVersion: [" + serverVersion + "], please use one of ['6', '7', '8'] for shellConfig.serverVersion");
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

        @NotNull
        @Override
        public ClassVisitor wrap(@NotNull TypeDescription instrumentedType,
                                 @NotNull ClassVisitor classVisitor,
                                 @NotNull Implementation.Context implementationContext,
                                 @NotNull TypePool typePool,
                                 @NotNull FieldList<FieldDescription.InDefinedShape> fields,
                                 @NotNull MethodList<?> methods,
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
