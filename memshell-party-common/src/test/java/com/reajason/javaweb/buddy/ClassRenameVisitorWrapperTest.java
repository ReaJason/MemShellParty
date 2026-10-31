package com.reajason.javaweb.buddy;

import net.bytebuddy.ByteBuddy;
import net.bytebuddy.description.type.TypeDescription;
import net.bytebuddy.dynamic.ClassFileLocator;
import net.bytebuddy.pool.TypePool;
import org.junit.jupiter.api.Test;
import org.objectweb.asm.ClassReader;
import org.objectweb.asm.ClassVisitor;
import org.objectweb.asm.ClassWriter;
import org.objectweb.asm.FieldVisitor;
import org.objectweb.asm.Opcodes;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;

class ClassRenameVisitorWrapperTest {

    @Test
    void classRenameMovesTheClassAndItsInnerClasses() throws Exception {
        byte[] bytes = classWithFields("sample/Outer",
                "Lsample/Outer;",
                "Lsample/Outer$Inner;",
                "Lsample/Outer$Inner$Deeper;",
                "Lsample/OuterBar;",
                "Ljava/lang/String;");

        byte[] renamed = rename(bytes, "sample.Outer", "moved.Moved");

        assertEquals("moved/Moved", new ClassReader(renamed).getClassName());
        assertEquals(Arrays.asList(
                "Lmoved/Moved;",
                "Lmoved/Moved$Inner;",
                "Lmoved/Moved$Inner$Deeper;",
                "Lsample/OuterBar;",
                "Ljava/lang/String;"), fieldDescriptors(renamed));
    }

    @Test
    void packageRenameMovesTheWholeSubtreeOnly() throws Exception {
        byte[] bytes = classWithFields("sample/pkg/Bean",
                "Lsample/pkg/Bean;",
                "Lsample/pkg/Other;",
                "Lsample/pkgdeep/Other;",
                "Lsample/pkg$Odd;");

        byte[] renamed = rename(bytes, ClassRenameVisitorWrapper.forPackage("sample.pkg", "moved.place"));

        assertEquals("moved/place/Bean", new ClassReader(renamed).getClassName());
        assertEquals(Arrays.asList(
                "Lmoved/place/Bean;",
                "Lmoved/place/Other;",
                "Lsample/pkgdeep/Other;",
                "Lsample/pkg$Odd;"), fieldDescriptors(renamed));
    }

    private static byte[] rename(byte[] bytes, String originalName, String newName) throws Exception {
        return rename(bytes, new ClassRenameVisitorWrapper(originalName, newName));
    }

    private static byte[] rename(byte[] bytes, ClassRenameVisitorWrapper wrapper) throws Exception {
        String className = new ClassReader(bytes).getClassName().replace('/', '.');
        ClassFileLocator locator = new MissingTypeLocator(new ClassFileLocator.Compound(
                ClassFileLocator.Simple.of(className, bytes),
                ClassFileLocator.ForClassLoader.ofSystemLoader()));
        TypePool typePool = TypePool.Default.of(locator);
        TypeDescription type = typePool.describe(className).resolve();
        return new ByteBuddy().redefine(type, locator)
                .visit(wrapper)
                .make(typePool)
                .getBytes();
    }

    private static byte[] classWithFields(String internalName, String... descriptors) {
        ClassWriter writer = new ClassWriter(0);
        writer.visit(Opcodes.V1_8, Opcodes.ACC_PUBLIC, internalName, null, "java/lang/Object", null);
        for (int i = 0; i < descriptors.length; i++) {
            FieldVisitor field = writer.visitField(Opcodes.ACC_PUBLIC, "field" + i, descriptors[i],
                    null, null);
            field.visitEnd();
        }
        writer.visitEnd();
        return writer.toByteArray();
    }

    private static List<String> fieldDescriptors(byte[] bytes) {
        final List<String> descriptors = new ArrayList<String>();
        new ClassReader(bytes).accept(new ClassVisitor(Opcodes.ASM9) {
            @Override
            public FieldVisitor visitField(int access, String name, String descriptor,
                                           String signature, Object value) {
                descriptors.add(descriptor);
                return null;
            }
        }, 0);
        return descriptors;
    }
}
