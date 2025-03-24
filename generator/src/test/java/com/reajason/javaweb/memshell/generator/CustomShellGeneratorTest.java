package com.reajason.javaweb.memshell.generator;

import com.reajason.javaweb.memshell.config.CustomConfig;
import com.reajason.javaweb.memshell.config.ShellConfig;
import com.reajason.javaweb.memshell.utils.CommonUtil;
import lombok.SneakyThrows;
import net.bytebuddy.ByteBuddy;
import net.bytebuddy.jar.asm.ClassReader;
import org.apache.commons.codec.binary.Base64;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;

/**
 * @author ReaJason
 * @since 2025/3/19
 */
class CustomShellGeneratorTest {

    @Test
    @SneakyThrows
    void test() {
        byte[] bytes = new ByteBuddy()
                .subclass(Object.class)
                .name(CommonUtil.generateShellClassName()).make().getBytes();
        String className = CommonUtil.generateShellClassName();
        byte[] bytes1 = new CustomShellGenerator(ShellConfig.builder().build(), CustomConfig.builder().shellClassName(className).shellClassBase64(Base64.encodeBase64String(bytes)).build()).getBytes();

        ClassReader classReader = new ClassReader(bytes1);
        assertEquals(className, classReader.getClassName().replace("/", "."));
    }
}