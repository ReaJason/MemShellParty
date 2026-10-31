package com.reajason.javaweb.asm;

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
        final String oldClassName = relocateClassPackage.replace('.', '/');
        final String newClassName = relocatePrefix.replace('.', '/');
        ClassWriter writer = new ClassWriter(reader, ClassWriter.COMPUTE_MAXS);
        ClassRemapper adapter = new ClassRemapper(writer, new Remapper(Opcodes.ASM9) {
            @Override
            public String map(String typeName) {
                if (typeName.equals(oldClassName)) {
                    return newClassName;
                }
                if (typeName.startsWith(oldClassName + "/")) {
                    return newClassName + typeName.substring(oldClassName.length());
                }
                return typeName;
            }
        });
        reader.accept(adapter, 0);
        return writer.toByteArray();
    }

    public static byte[] relocateJakarta(byte[] classBytes) {
        return relocate(classBytes, "javax", "jakarta");
    }

    /**
     * 将 jakarta.servlet / jakarta.websocket 改成对应的 javax 类名，是 {@link #relocateJakarta(byte[])} 的逆向操作。
     * <p>
     * 自定义内存马可能由 jakarta API 编译，而生成期类路径上只有 javax API（ByteBuddy 解析类型时不能缺失），
     * 所以先归一化成 javax 再交给 ByteBuddy；生成完成后由 JakartaPostProcessor 按目标挂载类型改回 jakarta。
     */
    public static byte[] relocateJavax(byte[] classBytes) {
        return relocate(classBytes, "jakarta", "javax");
    }

    private static byte[] relocate(byte[] classBytes, String sourcePrefix, String targetPrefix) {
        ClassReader reader = getClassReader(classBytes);
        ClassWriter writer = new ClassWriter(reader, ClassWriter.COMPUTE_MAXS);
        ClassRemapper adapter = new ClassRemapper(writer, new Remapper(Opcodes.ASM9) {
            @Override
            public String map(String typeName) {
                if (typeName.startsWith(sourcePrefix + "/servlet/")
                        || typeName.startsWith(sourcePrefix + "/websocket/")) {
                    return typeName.replaceFirst(sourcePrefix, targetPrefix);
                } else {
                    return typeName;
                }
            }
        });
        reader.accept(adapter, 0);
        return writer.toByteArray();
    }

    private static ClassReader getClassReader(byte[] classBytes) {
        ClassReader reader = null;
        try {
            reader = new ClassReader(classBytes);
        } catch (Exception e) {
            throw new RuntimeException("invalid class bytes");
        }
        return reader;
    }
}
