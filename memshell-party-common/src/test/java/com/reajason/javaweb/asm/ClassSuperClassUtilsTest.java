package com.reajason.javaweb.asm;

import net.bytebuddy.ByteBuddy;
import org.junit.jupiter.api.Test;
import org.objectweb.asm.ClassReader;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

/**
 * @author ReaJason
 * @since 2025/11/19
 */
class ClassSuperClassUtilsTest {
    @Test
    void test() {
        String superClassName = "com.sun.org.apache.xalan.internal.xsltc.runtime.AbstractTranslet";
        byte[] bytes = new ByteBuddy().redefine(EmptySuperClass.class).make().getBytes();
        byte[] newBytes = ClassSuperClassUtils.addSuperClass(bytes, superClassName);
        assertEquals("java/lang/Object", new ClassReader(bytes).getSuperName());
        assertEquals(superClassName.replace(".", "/"), new ClassReader(newBytes).getSuperName());
    }

    @Test
    void testException() {
        String superClassName = "com.sun.org.apache.xalan.internal.xsltc.runtime.AbstractTranslet";
        byte[] bytes = new ByteBuddy().redefine(SuperClass.class).make().getBytes();
        assertThrows(IllegalStateException.class, () -> ClassSuperClassUtils.addSuperClass(bytes, superClassName));
    }

    class EmptySuperClass {

    }

    class SuperClass extends EmptySuperClass {
    }
}