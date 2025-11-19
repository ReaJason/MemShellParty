package com.reajason.javaweb.asm;

import net.bytebuddy.ByteBuddy;
import org.junit.jupiter.api.Test;
import org.objectweb.asm.ClassReader;

import javax.script.ScriptEngine;
import javax.script.ScriptEngineFactory;
import java.io.Serializable;
import java.util.Collections;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;

/**
 * @author ReaJason
 * @since 2025/11/16
 */
class ClassInterfaceUtilsTest {

    @Test
    void test() {
        String interfaceName = "javax.script.ScriptEngineFactory";
        byte[] bytes = new ByteBuddy().redefine(EmptyInterface.class).make().getBytes();
        byte[] newBytes = ClassInterfaceUtils.addInterface(bytes, interfaceName);
        String[] interfaces = new ClassReader(newBytes).getInterfaces();
        assertEquals(1, interfaces.length);
        assertEquals(interfaceName.replace(".", "/"), interfaces[0]);
    }

    @Test
    void skipAdd(){
        String interfaceName = "javax.script.ScriptEngineFactory";
        byte[] bytes = new ByteBuddy().redefine(ScriptEngineFactoryClass.class).make().getBytes();
        byte[] newBytes = ClassInterfaceUtils.addInterface(bytes, interfaceName);
        String[] interfaces = new ClassReader(newBytes).getInterfaces();
        assertEquals(1, interfaces.length);
        assertEquals(interfaceName.replace(".", "/"), interfaces[0]);
    }

    @Test
    void addNewInterface(){
        String interfaceName = "javax.script.ScriptEngineFactory";
        byte[] bytes = new ByteBuddy().redefine(Entity.class).make().getBytes();
        byte[] newBytes = ClassInterfaceUtils.addInterface(bytes, interfaceName);
        String[] interfaces = new ClassReader(newBytes).getInterfaces();
        assertEquals(2, interfaces.length);
        assertEquals("java/io/Serializable", interfaces[0]);
        assertEquals(interfaceName.replace(".", "/"), interfaces[1]);
    }

    static class EmptyInterface {
    }

    static class ScriptEngineFactoryClass implements ScriptEngineFactory {
        @Override
        public String getEngineName() {
            return "";
        }

        @Override
        public String getEngineVersion() {
            return "";
        }

        @Override
        public List<String> getExtensions() {
            return Collections.emptyList();
        }

        @Override
        public List<String> getMimeTypes() {
            return Collections.emptyList();
        }

        @Override
        public List<String> getNames() {
            return Collections.emptyList();
        }

        @Override
        public String getLanguageName() {
            return "";
        }

        @Override
        public String getLanguageVersion() {
            return "";
        }

        @Override
        public Object getParameter(String key) {
            return null;
        }

        @Override
        public String getMethodCallSyntax(String obj, String m, String... args) {
            return "";
        }

        @Override
        public String getOutputStatement(String toDisplay) {
            return "";
        }

        @Override
        public String getProgram(String... statements) {
            return "";
        }

        @Override
        public ScriptEngine getScriptEngine() {
            return null;
        }
    }

    static class Entity implements Serializable {

    }
}