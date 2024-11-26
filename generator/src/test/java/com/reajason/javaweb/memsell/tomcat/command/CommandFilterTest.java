package com.reajason.javaweb.memsell.tomcat.command;

import com.reajason.javaweb.memsell.CommandGenerator;
import com.reajason.javaweb.util.ClassUtils;
import org.apache.commons.codec.binary.Base64;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;

/**
 * @author ReaJason
 * @since 2024/11/24
 */
class CommandFilterTest {

    @Test
    void testGenerate() {
        String className = "org.command.CommandFilter";
        String headerName = "cmd";
        byte[] bytes = CommandGenerator.generate(CommandFilter.class, className, headerName);
        Object obj = ClassUtils.newInstance(bytes);
        assertEquals(className, obj.getClass().getName());
        assertEquals(headerName, ClassUtils.getFieldValue(obj, "headerName"));
        System.out.println(Base64.encodeBase64String(bytes));
    }
}