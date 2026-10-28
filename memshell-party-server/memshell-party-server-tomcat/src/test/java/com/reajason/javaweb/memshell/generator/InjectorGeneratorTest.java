package com.reajason.javaweb.memshell.generator;

import com.reajason.javaweb.agent.AgentPersistence;
import com.reajason.javaweb.memshell.config.InjectorConfig;
import com.reajason.javaweb.memshell.config.ShellConfig;
import com.reajason.javaweb.memshell.injector.tomcat.TomcatFilterChainAgentInjector;
import org.junit.jupiter.api.Test;

import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertFalse;
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
                .injectorTemplateClassName(TomcatFilterChainAgentInjector.class.getName())
                .injectorTemplateClassLoader(TomcatFilterChainAgentInjector.class.getClassLoader())
                .build();
        InjectorGenerator injectorGenerator = new InjectorGenerator(ShellConfig.builder().build(), injectorConfig);
//        injectorGenerator.generate();
        Map<String, byte[]> innerClassBytes = injectorGenerator.getInnerClassBytes();
//        assertEquals(4, innerClassBytes.size());
        assertTrue(innerClassBytes.containsKey(AgentPersistence.class.getName()));
        assertTrue(innerClassBytes.containsKey(AgentPersistence.Transformer.class.getName()));
        innerClassBytes.forEach((innerClassName, value) -> assertTrue(
                innerClassName.startsWith(injectorConfig.getInjectorClassName())
                        || innerClassName.startsWith(AgentPersistence.class.getName())));
    }

    @Test
    void nonPersistentTemplateSkipsPersistenceClasses() {
        InjectorConfig injectorConfig = InjectorConfig.builder()
                .shellClassBytes("hello".getBytes())
                .shellClassName("hello")
                .injectorClassName("test.NonPersistentAgent")
                .injectorTemplateClassName(NonPersistentTemplate.class.getName())
                .injectorTemplateClassLoader(NonPersistentTemplate.class.getClassLoader())
                .build();
        InjectorGenerator injectorGenerator = new InjectorGenerator(ShellConfig.builder().build(), injectorConfig);

        Map<String, byte[]> innerClassBytes = injectorGenerator.getInnerClassBytes();

        assertTrue(innerClassBytes.containsKey("test.NonPersistentAgent$Nested"));
        assertFalse(innerClassBytes.keySet().stream()
                .anyMatch(name -> name.startsWith(AgentPersistence.class.getName())));
    }

    public static class NonPersistentTemplate {
        public static class Nested {
        }
    }
}