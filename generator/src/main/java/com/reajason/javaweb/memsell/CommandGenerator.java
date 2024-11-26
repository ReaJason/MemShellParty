package com.reajason.javaweb.memsell;

import net.bytebuddy.ByteBuddy;
import net.bytebuddy.dynamic.DynamicType;
import net.bytebuddy.implementation.FieldAccessor;
import net.bytebuddy.implementation.Implementation;
import net.bytebuddy.implementation.SuperMethodCall;
import net.bytebuddy.matcher.ElementMatchers;

/**
 * @author ReaJason
 * @since 2024/11/24
 */
public class CommandGenerator {

    public static byte[] generate(Class<?> commandClass, String commandClassName, String headerName) {
        Implementation.Composable fieldSets = SuperMethodCall.INSTANCE
                .andThen(FieldAccessor.ofField("headerName").setsValue(headerName));
        try (DynamicType.Unloaded<?> make = new ByteBuddy()
                .redefine(commandClass)
                .name(commandClassName)
                .constructor(ElementMatchers.any())
                .intercept(fieldSets)
                .make()) {
            return make.getBytes();
        }
    }
}
