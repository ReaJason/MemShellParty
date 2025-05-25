package com.reajason.javaweb.memshell.generator;

import com.reajason.javaweb.memshell.config.InjectorConfig;
import com.reajason.javaweb.memshell.config.ShellConfig;
import com.reajason.javaweb.memshell.injector.tomcat.TomcatFilterChainAgentInjector;
import org.junit.jupiter.api.Test;

import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * @author ReaJason
 * @since 2025/3/27
 */
class InjectorGeneratorTest {

    @Test
    void testAsm() {
        InjectorConfig injectorConfig = InjectorConfig.builder()
                .shellClassBytes("hello".getBytes())
                .shellClassName("hello")
                .injectorClass(TomcatFilterChainAgentInjector.class)
                .build();
        InjectorGenerator injectorGenerator = new InjectorGenerator(ShellConfig.builder().build(), injectorConfig);
//        injectorGenerator.generate();
        Map<String, byte[]> innerClassBytes = injectorGenerator.getInnerClassBytes();
//        assertEquals(4, innerClassBytes.size());
        innerClassBytes.forEach((innerClassName, value) -> assertTrue(innerClassName.startsWith(injectorConfig.getInjectorClassName())));
    }
}