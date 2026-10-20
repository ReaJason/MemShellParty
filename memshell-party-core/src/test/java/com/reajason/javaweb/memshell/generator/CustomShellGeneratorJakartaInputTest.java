package com.reajason.javaweb.memshell.generator;

import com.reajason.javaweb.Server;
import com.reajason.javaweb.asm.ClassReferenceVisitor;
import com.reajason.javaweb.memshell.ShellTool;
import com.reajason.javaweb.memshell.ShellType;
import com.reajason.javaweb.memshell.config.ShellConfig;
import com.reajason.javaweb.memshell.custom.CustomConfig;
import org.junit.jupiter.api.Test;
import org.objectweb.asm.ClassReader;
import org.objectweb.asm.ClassWriter;
import org.objectweb.asm.MethodVisitor;
import org.objectweb.asm.Opcodes;

import java.util.Base64;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * 自定义内存马可能由 jakarta API 编译。生成期只保留 javax API，字节码在交给 ByteBuddy 之前
 * 需要先归一化成 javax，否则 TypePool 解析 jakarta.servlet/websocket 类型会失败。
 */
class CustomShellGeneratorJakartaInputTest {

    @Test
    void jakartaCompiledShellIsNormalizedBeforeGeneration() {
        // 前提：测试运行期没有 jakarta API，否则这条路径就失去验证意义
        assertThrows(ClassNotFoundException.class,
                () -> CustomShellGenerator.class.getClassLoader().loadClass("jakarta.servlet.Filter"));

        Set<String> references = references(generateShell(ShellType.SERVLET));
        assertTrue(references.contains("javax/servlet/Filter"));
        // Servlet 4 才有的类型：保证生成期 javax API 版本足够新（Jakarta Servlet 5 的对应面）
        assertTrue(references.contains("javax/servlet/http/HttpServletMapping"));
        assertFalse(references.contains("jakarta/servlet/Filter"));
    }

    @Test
    void jakartaCompiledShellIsConvertedBackForJakartaShellType() {
        Set<String> references = references(generateShell(ShellType.JAKARTA_SERVLET));
        assertTrue(references.contains("jakarta/servlet/Filter"));
        assertTrue(references.contains("jakarta/servlet/http/HttpServletMapping"));
        assertFalse(references.contains("javax/servlet/Filter"));
    }

    private static byte[] generateShell(String shellType) {
        ShellConfig shellConfig = ShellConfig.builder()
                .server(Server.Tomcat)
                .serverVersion("10")
                .shellTool(ShellTool.Custom)
                .shellType(shellType)
                .build();
        CustomConfig customConfig = CustomConfig.builder()
                .shellClassName("com.example.JakartaFilterShell")
                .shellClassBase64(Base64.getEncoder().encodeToString(jakartaFilter()))
                .build();
        return new CustomShellGenerator(shellConfig, customConfig).getBytes();
    }

    private static Set<String> references(byte[] classBytes) {
        ClassReferenceVisitor visitor = new ClassReferenceVisitor();
        new ClassReader(classBytes).accept(visitor, 0);
        return visitor.getReferencedClasses();
    }

    /**
     * 生成一个用 jakarta API 编译的 Filter 类；测试编译期不需要 jakarta 依赖。
     */
    private static byte[] jakartaFilter() {
        ClassWriter writer = new ClassWriter(ClassWriter.COMPUTE_MAXS);
        writer.visit(Opcodes.V1_8, Opcodes.ACC_PUBLIC | Opcodes.ACC_SUPER,
                "test/JakartaFilterFixture", null, "java/lang/Object",
                new String[]{"jakarta/servlet/Filter", "jakarta/servlet/http/HttpServletMapping"});

        MethodVisitor constructor = writer.visitMethod(Opcodes.ACC_PUBLIC, "<init>", "()V", null, null);
        constructor.visitCode();
        constructor.visitVarInsn(Opcodes.ALOAD, 0);
        constructor.visitMethodInsn(Opcodes.INVOKESPECIAL, "java/lang/Object", "<init>", "()V", false);
        constructor.visitInsn(Opcodes.RETURN);
        constructor.visitMaxs(0, 0);
        constructor.visitEnd();

        MethodVisitor doFilter = writer.visitMethod(Opcodes.ACC_PUBLIC, "doFilter",
                "(Ljakarta/servlet/ServletRequest;Ljakarta/servlet/ServletResponse;Ljakarta/servlet/FilterChain;)V",
                null, new String[]{"java/io/IOException", "jakarta/servlet/ServletException"});
        doFilter.visitCode();
        doFilter.visitInsn(Opcodes.RETURN);
        doFilter.visitMaxs(0, 0);
        doFilter.visitEnd();

        MethodVisitor init = writer.visitMethod(Opcodes.ACC_PUBLIC, "init",
                "(Ljakarta/servlet/FilterConfig;)V", null, new String[]{"jakarta/servlet/ServletException"});
        init.visitCode();
        init.visitInsn(Opcodes.RETURN);
        init.visitMaxs(0, 0);
        init.visitEnd();

        MethodVisitor destroy = writer.visitMethod(Opcodes.ACC_PUBLIC, "destroy", "()V", null, null);
        destroy.visitCode();
        destroy.visitInsn(Opcodes.RETURN);
        destroy.visitMaxs(0, 0);
        destroy.visitEnd();

        writer.visitEnd();
        return writer.toByteArray();
    }
}
