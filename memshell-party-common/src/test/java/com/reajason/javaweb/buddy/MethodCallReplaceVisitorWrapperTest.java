package com.reajason.javaweb.buddy;

import net.bytebuddy.ByteBuddy;
import net.bytebuddy.dynamic.DynamicType;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;

/**
 * @author ReaJason
 * @since 2025/2/22
 */
class MethodCallReplaceVisitorWrapperTest {

    public static class ExternalClass {
        public static String externalMethod(String input) {
            return "External: " + input;
        }

        public static String replacementMethod(String input) {
            return "Replaced: " + input;
        }
    }

    public static class TargetClass {
        public String targetMethod(String input) {
            System.out.println("targetMethod");
            return ExternalClass.replacementMethod(input);
        }

        public static String replacementMethod(String input) {
            return "Replaced: " + input;
        }
    }

    @Test
    void test() throws Exception {
        String newClassName = TargetClass.class.getName() + "Redefinition";
        DynamicType.Unloaded<TargetClass> dynamicType = new ByteBuddy()
                .redefine(TargetClass.class)
                .name(newClassName)
                .visit(MethodCallReplaceVisitorWrapper.newInstance(
                        "targetMethod", newClassName, ExternalClass.class.getName()))
                .make();
        Class<?> redefinedClass = dynamicType.load(MethodCallReplaceVisitorWrapperTest.class.getClassLoader())
                .getLoaded();
        Object object = redefinedClass.newInstance();
        Object result = object.getClass().getMethod("targetMethod", String.class).invoke(object, "xixi");
        assertEquals("Replaced: xixi", result);
    }
}