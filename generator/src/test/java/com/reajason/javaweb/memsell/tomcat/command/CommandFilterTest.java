package com.reajason.javaweb.memsell.tomcat.command;

import com.reajason.javaweb.config.Constants;
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
        String paramName = "cmd";
        byte[] bytes = CommandGenerator.generate(CommandFilter.class, className, paramName, false, Constants.DEFAULT_VERSION);
        Object obj = ClassUtils.newInstance(bytes);
        assertEquals(className, obj.getClass().getName());
        assertEquals(paramName, ClassUtils.getFieldValue(obj, "paramName"));
        System.out.println(Base64.encodeBase64String(bytes));
    }
}