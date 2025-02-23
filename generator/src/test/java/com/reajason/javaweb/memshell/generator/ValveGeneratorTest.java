package com.reajason.javaweb.memshell.generator;

import com.reajason.javaweb.memshell.shelltool.command.CommandValve;
import net.bytebuddy.jar.asm.ClassReader;
import net.bytebuddy.jar.asm.ClassVisitor;
import net.bytebuddy.jar.asm.Opcodes;
import org.junit.jupiter.api.Test;

import java.io.InputStream;

import static org.junit.jupiter.api.Assertions.assertEquals;

/**
 * @author ReaJason
 * @since 2025/2/22
 */
class ValveGeneratorTest {

    @Test
    void test() throws Exception {
        Class<?> clazz = ValveGenerator.generateValveClass(ValveGenerator.BES_VALVE_PACKAGE, CommandValve.class);
        InputStream resourceAsStream = clazz.getClassLoader().getResourceAsStream(clazz.getName().replace('.', '/') + ".class");
        assert resourceAsStream != null;
        ClassReader cr = new ClassReader(resourceAsStream);
        cr.accept(new ClassVisitor(Opcodes.ASM9) {
            @Override
            public void visit(int version, int access, String name, String signature, String superName, String[] interfaces) {
                assertEquals("com/bes/enterprise/webtier/Valve", interfaces[0]);
            }
        }, 0);
    }
}