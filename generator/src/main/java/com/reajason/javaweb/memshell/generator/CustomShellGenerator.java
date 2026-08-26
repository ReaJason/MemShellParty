package com.reajason.javaweb.memshell.generator;

import com.reajason.javaweb.memshell.config.CustomConfig;
import com.reajason.javaweb.memshell.config.ShellConfig;
import net.bytebuddy.ByteBuddy;
import net.bytebuddy.description.type.TypeDescription;
import net.bytebuddy.dynamic.ClassFileLocator;
import net.bytebuddy.dynamic.DynamicType;
import net.bytebuddy.jar.asm.ClassReader;
import net.bytebuddy.jar.asm.ClassVisitor;
import net.bytebuddy.jar.asm.Label;
import net.bytebuddy.jar.asm.MethodVisitor;
import net.bytebuddy.jar.asm.Opcodes;
import net.bytebuddy.pool.TypePool;
import org.apache.commons.lang3.StringUtils;

import java.util.Base64;

/**
 * @author ReaJason
 * @since 2025/3/18
 */
public class CustomShellGenerator extends ByteBuddyShellGenerator<CustomConfig> {
    private boolean containsSubroutines;

    public CustomShellGenerator(ShellConfig shellConfig, CustomConfig customConfig) {
        super(shellConfig, customConfig);
    }

    @Override
    protected DynamicType.Builder<?> getBuilder() {
        String shellClassBase64 = shellToolConfig.getShellClassBase64();
        byte[] classBytes = Base64.getDecoder().decode(shellClassBase64);
        ClassReader classReader = new ClassReader(classBytes);
        containsSubroutines = containsSubroutines(classReader);
        String className = classReader.getClassName().replace('/', '.');
        if (StringUtils.isBlank(shellToolConfig.getShellClassName())) {
            shellToolConfig.setShellClassName(className);
        }
        ClassFileLocator compoundLocator = new ClassFileLocator.Compound(
                ClassFileLocator.Simple.of(className, classBytes),
                ClassFileLocator.ForClassLoader.of(this.getClass().getClassLoader())
        );
        TypeDescription typeDescription = new TypePool.Default(
                new TypePool.CacheProvider.Simple(), compoundLocator,
                TypePool.Default.ReaderMode.FAST, TypePool.Default.ofSystemLoader()
        ).describe(className).resolve();
        shellToolConfig.setShellTypeDescription(typeDescription);
        return new ByteBuddy()
                .redefine(typeDescription, compoundLocator);
    }

    @Override
    protected int getTargetJreVersion() {
        // Byte Buddy cannot emit a class version newer than Java 5 when the
        // source bytecode contains legacy jsr/ret subroutines. Keep such
        // custom classes at Java 5; Java 6+ runtimes can load them as well.
        return containsSubroutines ? Opcodes.V1_5 : super.getTargetJreVersion();
    }

    private static boolean containsSubroutines(ClassReader classReader) {
        final boolean[] found = {false};
        classReader.accept(new ClassVisitor(Opcodes.ASM9) {
            @Override
            public MethodVisitor visitMethod(int access, String name, String descriptor,
                                             String signature, String[] exceptions) {
                return new MethodVisitor(Opcodes.ASM9) {
                    @Override
                    public void visitJumpInsn(int opcode, Label label) {
                        if (opcode == Opcodes.JSR) {
                            found[0] = true;
                        }
                    }

                    @Override
                    public void visitVarInsn(int opcode, int var) {
                        if (opcode == Opcodes.RET) {
                            found[0] = true;
                        }
                    }
                };
            }
        }, ClassReader.SKIP_DEBUG | ClassReader.SKIP_FRAMES);
        return found[0];
    }
}
