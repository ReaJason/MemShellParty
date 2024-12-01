package com.reajason.javaweb.memsell;

import com.reajason.javaweb.buddy.ByPassJdkModuleInterceptor;
import com.reajason.javaweb.buddy.ServletRenameVisitorWrapper;
import com.reajason.javaweb.buddy.TargetJDKVersionVisitorWrapper;
import net.bytebuddy.ByteBuddy;
import net.bytebuddy.dynamic.DynamicType;
import net.bytebuddy.implementation.FieldAccessor;
import net.bytebuddy.implementation.Implementation;
import net.bytebuddy.implementation.SuperMethodCall;
import net.bytebuddy.jar.asm.Opcodes;
import net.bytebuddy.matcher.ElementMatchers;

/**
 * @author ReaJason
 * @since 2024/11/24
 */
public class CommandGenerator {

    public static byte[] generate(Class<?> commandClass, String commandClassName, String paramName, boolean useJakarta, int targetJdkVersion) {
        Implementation.Composable fieldSets = SuperMethodCall.INSTANCE
                .andThen(FieldAccessor.ofField("paramName").setsValue(paramName));
        DynamicType.Builder<?> builder = new ByteBuddy()
                .redefine(commandClass)
                .name(commandClassName)
                .visit(new TargetJDKVersionVisitorWrapper(targetJdkVersion))
                .constructor(ElementMatchers.any()).intercept(fieldSets);
        if (targetJdkVersion >= Opcodes.V9) {
            builder = ByPassJdkModuleInterceptor.extend(builder);
        }
        if (useJakarta) {
            builder = builder.visit(ServletRenameVisitorWrapper.INSTANCE);
        }

        try (DynamicType.Unloaded<?> make = builder.make()) {
            return make.getBytes();
        }
    }
}