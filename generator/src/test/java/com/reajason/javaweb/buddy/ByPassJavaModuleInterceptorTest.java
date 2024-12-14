package com.reajason.javaweb.buddy;

import lombok.SneakyThrows;
import net.bytebuddy.ByteBuddy;
import net.bytebuddy.dynamic.DynamicType;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledOnJre;

import java.lang.reflect.InaccessibleObjectException;
import java.lang.reflect.Method;
import java.nio.file.Files;
import java.nio.file.Paths;

import static org.junit.jupiter.api.Assertions.*;
import static org.junit.jupiter.api.condition.JRE.JAVA_17;

/**
 * @author ReaJason
 * @since 2024/12/7
 */
class ByPassJavaModuleInterceptorTest {
    @Test
    @SneakyThrows
    @EnabledOnJre(JAVA_17)
    void testByPassModule() {
        Method defineClass = ClassLoader.class.getDeclaredMethod("defineClass", byte[].class, int.class, int.class);
        assertThrows(InaccessibleObjectException.class, () -> {
            defineClass.setAccessible(true);
        });
        ByPassJavaModuleInterceptor.enter(this.getClass());
        assertDoesNotThrow(() -> {
            defineClass.setAccessible(true);
        });
    }

}