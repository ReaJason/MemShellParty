package com.reajason.javaweb.asm;

import org.jetbrains.annotations.NotNull;
import org.objectweb.asm.ClassReader;
import org.objectweb.asm.ClassWriter;
import org.objectweb.asm.Opcodes;
import org.objectweb.asm.commons.ClassRemapper;
import org.objectweb.asm.commons.Remapper;
import org.objectweb.asm.commons.SimpleRemapper;

/**
 * @author ReaJason
 * @since 2025/3/29
 */
public class ClassRenameUtils {

    public static byte[] renameClass(byte[] classBytes, String newName) {
        ClassReader reader = getClassReader(classBytes);
        String oldClassName = reader.getClassName();
        String newClassName = newName.replace('.', '/');
        ClassWriter writer = new ClassWriter(reader, ClassWriter.COMPUTE_MAXS | ClassWriter.COMPUTE_FRAMES);
        ClassRemapper adapter = new ClassRemapper(writer, new SimpleRemapper(Opcodes.ASM9, oldClassName, newClassName));
        reader.accept(adapter, 0);
        return writer.toByteArray();
    }

    public static byte[] relocateClass(byte[] classBytes, String relocateClassPackage, String relocatePrefix) {
        ClassReader reader = getClassReader(classBytes);
        String oldClassName = relocateClassPackage.replace('.', '/');
        String newClassName = relocatePrefix.replace('.', '/');
        ClassWriter writer = new ClassWriter(reader, ClassWriter.COMPUTE_MAXS);
        ClassRemapper adapter = new ClassRemapper(writer, new Remapper(Opcodes.ASM9) {
            @Override
            public String map(String typeName) {
                if (typeName.startsWith(oldClassName)) {
                    return typeName.replaceFirst(oldClassName, newClassName);
                } else {
                    return typeName;
                }
            }
        });
        reader.accept(adapter, 0);
        return writer.toByteArray();
    }

    public static byte[] relocateJakarta(byte[] classBytes) {
        ClassReader reader = getClassReader(classBytes);
        ClassWriter writer = new ClassWriter(reader, ClassWriter.COMPUTE_MAXS);
        ClassRemapper adapter = new ClassRemapper(writer, new Remapper(Opcodes.ASM9) {
            @Override
            public String map(String typeName) {
                if (typeName.startsWith("javax/servlet/")
                        || typeName.startsWith("javax/websocket/")) {
                    return typeName.replaceFirst("javax", "jakarta");
                } else {
                    return typeName;
                }
            }
        });
        reader.accept(adapter, 0);
        return writer.toByteArray();
    }

    private static @NotNull ClassReader getClassReader(byte[] classBytes) {
        ClassReader reader = null;
        try {
            reader = new ClassReader(classBytes);
        } catch (Exception e) {
            throw new RuntimeException("invalid class bytes");
        }
        return reader;
    }
}
