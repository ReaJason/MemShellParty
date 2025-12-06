package com.reajason.javaweb.asm;

import lombok.SneakyThrows;
import net.bytebuddy.ByteBuddy;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;

/**
 * @author ReaJason
 * @since 2025/12/6
 */
class ClassAnnotationUtilsTest {
    @Test
    @SneakyThrows
    void test() {
        String interfaceName = "javax.script.ScriptEngineFactory";
        byte[] bytes = new ByteBuddy().redefine(ClassInterfaceUtilsTest.EmptyInterface.class).make().getBytes();
        List<ClassAnnotationUtils.AnnotationInfo> rawAnnotations = ClassAnnotationUtils.getAnnotations(bytes);
        byte[] newBytes = ClassAnnotationUtils.setAnnotation(bytes, interfaceName);
        List<ClassAnnotationUtils.AnnotationInfo> annotations = ClassAnnotationUtils.getAnnotations(newBytes);
        assertEquals(0, rawAnnotations.size());
        assertEquals(1, annotations.size());
        assertEquals("Ljavax/script/ScriptEngineFactory;", annotations.get(0).desc);
    }
}