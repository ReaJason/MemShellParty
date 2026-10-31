package com.reajason.javaweb.buddy;

import net.bytebuddy.dynamic.ClassFileLocator;
import org.objectweb.asm.ClassWriter;
import org.objectweb.asm.Opcodes;

import java.io.IOException;

/**
 * 单个 class 的旧外部类、父类或签名参数可能只存在于目标运行环境。
 * 为缺失类型提供仅供 Byte Buddy 读取的元数据桩，不加载类型，也不把桩写入结果。
 */
public final class MissingTypeLocator implements ClassFileLocator {
    private final ClassFileLocator delegate;

    public MissingTypeLocator(ClassFileLocator delegate) {
        this.delegate = delegate;
    }

    @Override
    public Resolution locate(String name) throws IOException {
        Resolution resolution = delegate.locate(name);
        if (resolution.isResolved()) {
            return resolution;
        }
        ClassWriter writer = new ClassWriter(0);
        writer.visit(Opcodes.V1_8, Opcodes.ACC_PUBLIC, name.replace('.', '/'), null,
                "java/lang/Object", null);
        writer.visitEnd();
        return new Resolution.Explicit(writer.toByteArray());
    }

    @Override
    public void close() throws IOException {
        delegate.close();
    }
}
