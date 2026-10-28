package com.reajason.javaweb.bytecode;

import com.reajason.javaweb.bytecode.fixtures.TriggerTarget;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.objectweb.asm.ClassReader;
import org.objectweb.asm.ClassVisitor;
import org.objectweb.asm.ClassWriter;
import org.objectweb.asm.FieldVisitor;
import org.objectweb.asm.Label;
import org.objectweb.asm.MethodVisitor;
import org.objectweb.asm.Opcodes;

import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.lang.reflect.Method;
import java.util.ArrayList;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * 字节码工具的行为验证：每个工具都真的改写字节码，并把结果装进独立 ClassLoader 跑一遍，
 * 用系统属性观察构造方法 / toString / 静态初始化是否按预期执行。
 */
class BytecodeToolServiceTest {

    private static final String FIXTURE = TriggerTarget.class.getName();

    private final BytecodeToolService service = new BytecodeToolService();
    private byte[] fixtureBytes;

    @BeforeEach
    void setUp() throws Exception {
        fixtureBytes = bytesOf(TriggerTarget.class);
        System.clearProperty(TriggerTarget.PROPERTY);
        System.clearProperty(TriggerTarget.CLINIT_PROPERTY);
    }

    // ------------------------------------------------------------------------------------
    // 转换 / 编码
    // ------------------------------------------------------------------------------------

    @Test
    void convertKeepsBytesAndResolvesClassName() {
        BytecodeToolService.TransformResult result = service.convert(fixtureBytes);

        assertArrayEquals(fixtureBytes, result.getClassBytes());
        assertEquals(FIXTURE, result.getClassName());
    }

    @Test
    void base64AndGzipBase64RoundTrip() {
        ClassBytesDecoder decoder = new ClassBytesDecoder();

        ClassBytesDecoder.DecodedClass plain = decoder.decodeBase64(
                ClassBytesEncoder.encode(fixtureBytes, false));
        assertArrayEquals(fixtureBytes, plain.getClassBytes());
        assertFalse(plain.isGzipped());

        ClassBytesDecoder.DecodedClass gzipped = decoder.decodeBase64(
                ClassBytesEncoder.encode(fixtureBytes, true));
        assertArrayEquals(fixtureBytes, gzipped.getClassBytes());
        assertTrue(gzipped.isGzipped());
    }

    // ------------------------------------------------------------------------------------
    // 修改父类 / 包名替换
    // ------------------------------------------------------------------------------------

    @Test
    void changeSuperClassRewritesSuperCall() {
        String abstractTranslet = "com.sun.org.apache.xalan.internal.xsltc.runtime.AbstractTranslet";

        byte[] result = service.changeClassInfo(fixtureBytes, abstractTranslet, null, null).getClassBytes();

        assertEquals("com/sun/org/apache/xalan/internal/xsltc/runtime/AbstractTranslet",
                new ClassReader(result).getSuperName());
        // 构造方法里的 Object.<init> 也要跟着改，否则新父类的构造函数不会执行
        // （夹具的 String 构造还会 new StringBuilder，别把它也算成 super 调用）
        List<String> constructorOwners = constructorOwners(result);
        assertTrue(constructorOwners.contains("com/sun/org/apache/xalan/internal/xsltc/runtime/AbstractTranslet"),
                constructorOwners.toString());
        assertFalse(constructorOwners.contains("java/lang/Object"), constructorOwners.toString());
    }

    @Test
    void relocatePackagePrefixRewritesDescriptors() {
        byte[] sample = sampleClassReferencing("javax/servlet/http/HttpServletRequest");

        byte[] result = service.changeClassInfo(sample, null, "javax.servlet", "jakarta.servlet").getClassBytes();

        assertEquals("Ljakarta/servlet/http/HttpServletRequest;", firstFieldDescriptor(result));
    }

    @Test
    void rejectsHalfFilledRelocation() {
        assertTrue(messageOf(() -> service.changeClassInfo(fixtureBytes, null, "javax.servlet", " ")).contains("同时填写"));
        assertTrue(messageOf(() -> service.changeClassInfo(fixtureBytes, null, " ", "jakarta.servlet")).contains("同时填写"));
    }

    @Test
    void rejectsSuperClassChangeOnInterface() {
        byte[] interfaceBytes = sampleInterface();

        assertTrue(messageOf(() -> service.changeClassInfo(interfaceBytes, "java.lang.Thread", null, null))
                .contains("接口不能修改父类"));
    }

    // ------------------------------------------------------------------------------------
    // 添加 main
    // ------------------------------------------------------------------------------------

    @Test
    void addMainInvokesStringConstructorWithFirstArgument() throws Exception {
        byte[] result = service.addMainMethod(fixtureBytes, "main",
                BytecodeToolService.ConstructorMode.ARGS_FIRST, null).getClassBytes();

        Class<?> clazz = load(FIXTURE, result);
        clazz.getMethod("main", String[].class).invoke(null, (Object) new String[]{"hello"});

        assertEquals("string:hello", System.getProperty(TriggerTarget.PROPERTY));
    }

    @Test
    void addMainAutoPrefersStringConstructor() throws Exception {
        byte[] result = service.addMainMethod(fixtureBytes, "main",
                BytecodeToolService.ConstructorMode.AUTO, null).getClassBytes();

        Class<?> clazz = load(FIXTURE, result);
        clazz.getMethod("main", String[].class).invoke(null, (Object) new String[]{"auto"});

        assertEquals("string:auto", System.getProperty(TriggerTarget.PROPERTY));
    }

    @Test
    void addUnderscoreMainWithLiteral() throws Exception {
        byte[] result = service.addMainMethod(fixtureBytes, "_main",
                BytecodeToolService.ConstructorMode.STRING_LITERAL, "literal").getClassBytes();

        Class<?> clazz = load(FIXTURE, result);
        clazz.getMethod("_main", String[].class).invoke(null, (Object) new String[0]);

        assertEquals("string:literal", System.getProperty(TriggerTarget.PROPERTY));
    }

    @Test
    void addMainNoArgUsesNoArgConstructor() throws Exception {
        byte[] result = service.addMainMethod(fixtureBytes, "main",
                BytecodeToolService.ConstructorMode.NO_ARG, null).getClassBytes();

        Class<?> clazz = load(FIXTURE, result);
        clazz.getMethod("main", String[].class).invoke(null, (Object) new String[0]);

        assertEquals("noarg", System.getProperty(TriggerTarget.PROPERTY));
    }

    @Test
    void rejectsDuplicateMainMethod() {
        byte[] once = service.addMainMethod(fixtureBytes, "main",
                BytecodeToolService.ConstructorMode.NO_ARG, null).getClassBytes();

        assertTrue(messageOf(() -> service.addMainMethod(once, "main",
                BytecodeToolService.ConstructorMode.NO_ARG, null)).contains("已存在"));
    }

    @Test
    void rejectsStringConstructorWhenClassHasOnlyNoArg() {
        byte[] noArgOnly = sampleClassWithNoArgConstructor();

        assertTrue(messageOf(() -> service.addMainMethod(noArgOnly, "main",
                BytecodeToolService.ConstructorMode.ARGS_FIRST, null)).contains("没有 (String) 构造方法"));
    }

    @Test
    void rejectsKeywordAsMethodName() {
        assertTrue(messageOf(() -> service.addMainMethod(fixtureBytes, "class",
                BytecodeToolService.ConstructorMode.NO_ARG, null)).contains("合法的 Java 标识符"));
    }

    // ------------------------------------------------------------------------------------
    // 静态初始化触发
    // ------------------------------------------------------------------------------------

    @Test
    void staticTriggerInvokesConstructor() throws Exception {
        byte[] result = service.addStaticTrigger(fixtureBytes,
                BytecodeToolService.TriggerMode.CONSTRUCTOR,
                BytecodeToolService.ConstructorMode.NO_ARG, null).getClassBytes();

        load(FIXTURE, result);

        assertEquals("noarg", System.getProperty(TriggerTarget.PROPERTY));
        assertEquals("yes", System.getProperty(TriggerTarget.CLINIT_PROPERTY), "原有静态初始化仍应执行");
    }

    @Test
    void staticTriggerInvokesToString() throws Exception {
        byte[] result = service.addStaticTrigger(fixtureBytes,
                BytecodeToolService.TriggerMode.TO_STRING,
                BytecodeToolService.ConstructorMode.NO_ARG, null).getClassBytes();

        load(FIXTURE, result);

        assertEquals("toString", System.getProperty(TriggerTarget.PROPERTY));
    }

    @Test
    void staticTriggerUsesLiteralStringConstructor() throws Exception {
        byte[] result = service.addStaticTrigger(fixtureBytes,
                BytecodeToolService.TriggerMode.CONSTRUCTOR,
                BytecodeToolService.ConstructorMode.STRING_LITERAL, "payload").getClassBytes();

        load(FIXTURE, result);

        assertEquals("string:payload", System.getProperty(TriggerTarget.PROPERTY));
    }

    /**
     * 输入类没有静态初始化块时，工具要自己补一个 <clinit>。
     */
    @Test
    void staticTriggerCreatesClinitWhenMissing() throws Exception {
        byte[] noClinit = sampleClassWithNoClinit();

        byte[] result = service.addStaticTrigger(noClinit,
                BytecodeToolService.TriggerMode.CONSTRUCTOR,
                BytecodeToolService.ConstructorMode.NO_ARG, null).getClassBytes();

        load("test.NoClinit", result);

        assertEquals("noarg", System.getProperty(TriggerTarget.PROPERTY));
    }

    // ------------------------------------------------------------------------------------
    // 随机类名 / 瘦身
    // ------------------------------------------------------------------------------------

    @Test
    void renameAndShrinkRemovesDebugInfoAndKeepsBehavior() throws Exception {
        BytecodeToolService.TransformResult result = service.renameAndShrink(
                fixtureBytes, null, null, true, true);

        String newName = result.getClassName();
        assertTrue(newName.startsWith(FIXTURE.substring(0, FIXTURE.lastIndexOf('.') + 1)),
                "随机改名默认保留原包名：" + newName);
        assertNotEquals(FIXTURE, newName);
        assertFalse(hasSourceFile(result.getClassBytes()), "SourceFile 应被清除");
        assertFalse(hasLineNumbers(result.getClassBytes()), "行号表应被清除");

        load(newName, result.getClassBytes());

        assertEquals("yes", System.getProperty(TriggerTarget.CLINIT_PROPERTY), "改名后静态初始化仍应执行");
    }

    @Test
    void renameToExplicitPackageAndName() {
        BytecodeToolService.TransformResult result = service.renameAndShrink(
                fixtureBytes, "RenamedShell", "com.example.generated", false, true);

        assertEquals("com.example.generated.RenamedShell", result.getClassName());
    }

    @Test
    void renameUpdatesSourceFileWhenDebugKept() {
        BytecodeToolService.TransformResult result = service.renameAndShrink(
                fixtureBytes, "RenamedShell", null, false, false);

        assertEquals("com.reajason.javaweb.bytecode.fixtures.RenamedShell",
                result.getClassName());
        assertEquals("RenamedShell.java", sourceFileOf(result.getClassBytes()));
    }

    @Test
    void rejectsClassNameContainingPackageWhenPackageAlsoGiven() {
        assertTrue(messageOf(() -> service.renameAndShrink(
                fixtureBytes, "com.example.Shell", "com.other", false, true)).contains("已包含包名"));
    }

    @Test
    void rejectsInvalidClassName() {
        assertTrue(messageOf(() -> service.renameAndShrink(
                fixtureBytes, "1Bad", null, false, true)).contains("不是合法的类名"));
    }

    // ------------------------------------------------------------------------------------
    // 模块绕过
    // ------------------------------------------------------------------------------------

    @Test
    void moduleBypassMakesClassBelongToJavaBase() throws Exception {
        final Method getModule;
        try {
            getModule = Class.class.getMethod("getModule");
        } catch (NoSuchMethodException ex) {
            Assumptions.assumeTrue(false, "JDK 8 没有模块系统");
            return;
        }

        byte[] result = service.addModuleBypass(fixtureBytes).getClassBytes();

        Class<?> clazz = load(FIXTURE, result);

        assertEquals("yes", System.getProperty(TriggerTarget.CLINIT_PROPERTY), "原有静态初始化仍应执行");
        assertEquals(getModule.invoke(Object.class), getModule.invoke(clazz),
                "静态初始化应把当前类的 module 改成 java.base");
    }

    // ------------------------------------------------------------------------------------
    // 测试辅助
    // ------------------------------------------------------------------------------------

    private static byte[] bytesOf(Class<?> type) throws Exception {
        String resource = type.getSimpleName() + ".class";
        InputStream in = type.getResourceAsStream(resource);
        assertNotNull(in, "找不到类字节：" + resource);
        try {
            ByteArrayOutputStream out = new ByteArrayOutputStream();
            byte[] buffer = new byte[8192];
            int read;
            while ((read = in.read(buffer)) != -1) {
                out.write(buffer, 0, read);
            }
            return out.toByteArray();
        } finally {
            in.close();
        }
    }

    /**
     * 子优先加载：测试类路径上也有同名类，必须让改写后的字节覆盖它。
     */
    private static Class<?> load(final String binaryName, final byte[] bytes) throws Exception {
        ClassLoader parent = ClassLoader.getSystemClassLoader().getParent();
        ClassLoader loader = new ClassLoader(parent) {
            @Override
            protected Class<?> loadClass(String name, boolean resolve) throws ClassNotFoundException {
                if (!binaryName.equals(name)) {
                    return super.loadClass(name, resolve);
                }
                Class<?> loaded = findLoadedClass(name);
                if (loaded == null) {
                    loaded = defineClass(name, bytes, 0, bytes.length);
                }
                if (resolve) {
                    resolveClass(loaded);
                }
                return loaded;
            }
        };
        return Class.forName(binaryName, true, loader);
    }

    private static List<String> constructorOwners(byte[] classBytes) {
        final List<String> owners = new ArrayList<String>();
        new ClassReader(classBytes).accept(new ClassVisitor(Opcodes.ASM9) {
            @Override
            public MethodVisitor visitMethod(int access, String name, String descriptor,
                                             String signature, String[] exceptions) {
                if (!"<init>".equals(name)) {
                    return null;
                }
                return new MethodVisitor(Opcodes.ASM9) {
                    @Override
                    public void visitMethodInsn(int opcode, String owner, String name,
                                                String descriptor, boolean isInterface) {
                        if (opcode == Opcodes.INVOKESPECIAL && "<init>".equals(name)) {
                            owners.add(owner);
                        }
                    }
                };
            }
        }, 0);
        return owners;
    }

    private static String firstFieldDescriptor(byte[] classBytes) {
        final String[] descriptor = new String[1];
        new ClassReader(classBytes).accept(new ClassVisitor(Opcodes.ASM9) {
            @Override
            public FieldVisitor visitField(int access, String name, String fieldDescriptor,
                                           String signature, Object value) {
                descriptor[0] = fieldDescriptor;
                return null;
            }
        }, 0);
        return descriptor[0];
    }

    private static boolean hasSourceFile(byte[] classBytes) {
        final boolean[] found = {false};
        new ClassReader(classBytes).accept(new ClassVisitor(Opcodes.ASM9) {
            @Override
            public void visitSource(String source, String debug) {
                found[0] = true;
            }
        }, 0);
        return found[0];
    }

    private static String sourceFileOf(byte[] classBytes) {
        final String[] source = new String[1];
        new ClassReader(classBytes).accept(new ClassVisitor(Opcodes.ASM9) {
            @Override
            public void visitSource(String file, String debug) {
                source[0] = file;
            }
        }, 0);
        return source[0];
    }

    private static boolean hasLineNumbers(byte[] classBytes) {
        final boolean[] found = {false};
        new ClassReader(classBytes).accept(new ClassVisitor(Opcodes.ASM9) {
            @Override
            public MethodVisitor visitMethod(int access, String name, String descriptor,
                                             String signature, String[] exceptions) {
                return new MethodVisitor(Opcodes.ASM9) {
                    @Override
                    public void visitLineNumber(int line, Label start) {
                        found[0] = true;
                    }
                };
            }
        }, 0);
        return found[0];
    }

    private static String messageOf(Runnable action) {
        try {
            action.run();
        } catch (IllegalArgumentException ex) {
            return ex.getMessage() == null ? "" : ex.getMessage();
        }
        throw new AssertionError("应当抛出 IllegalArgumentException");
    }

    private static byte[] sampleClassReferencing(String fieldType) {
        ClassWriter writer = new ClassWriter(0);
        writer.visit(Opcodes.V1_8, Opcodes.ACC_PUBLIC, "test/Sample", null, "java/lang/Object", null);
        writer.visitField(Opcodes.ACC_PUBLIC, "request", "L" + fieldType + ";", null, null).visitEnd();
        writer.visitEnd();
        return writer.toByteArray();
    }

    private static byte[] sampleInterface() {
        ClassWriter writer = new ClassWriter(0);
        writer.visit(Opcodes.V1_8, Opcodes.ACC_PUBLIC | Opcodes.ACC_ABSTRACT | Opcodes.ACC_INTERFACE,
                "test/SampleInterface", null, "java/lang/Object", null);
        writer.visitEnd();
        return writer.toByteArray();
    }

    /**
     * 只有无参构造、没有静态初始化块的类，用来验证「补 <clinit>」与构造方法能力判断。
     */
    private static byte[] sampleClassWithNoArgConstructor() {
        ClassWriter writer = new ClassWriter(0);
        writer.visit(Opcodes.V1_8, Opcodes.ACC_PUBLIC, "test/NoArgOnly", null, "java/lang/Object", null);
        MethodVisitor mv = writer.visitMethod(Opcodes.ACC_PUBLIC, "<init>", "()V", null, null);
        mv.visitCode();
        mv.visitVarInsn(Opcodes.ALOAD, 0);
        mv.visitMethodInsn(Opcodes.INVOKESPECIAL, "java/lang/Object", "<init>", "()V", false);
        mv.visitInsn(Opcodes.RETURN);
        mv.visitMaxs(1, 1);
        mv.visitEnd();
        writer.visitEnd();
        return writer.toByteArray();
    }

    private static byte[] sampleClassWithNoClinit() {
        ClassWriter writer = new ClassWriter(0);
        writer.visit(Opcodes.V1_8, Opcodes.ACC_PUBLIC, "test/NoClinit", null, "java/lang/Object", null);
        MethodVisitor mv = writer.visitMethod(Opcodes.ACC_PUBLIC, "<init>", "()V", null, null);
        mv.visitCode();
        mv.visitVarInsn(Opcodes.ALOAD, 0);
        mv.visitMethodInsn(Opcodes.INVOKESPECIAL, "java/lang/Object", "<init>", "()V", false);
        mv.visitLdcInsn(TriggerTarget.PROPERTY);
        mv.visitLdcInsn("noarg");
        mv.visitMethodInsn(Opcodes.INVOKESTATIC, "java/lang/System", "setProperty",
                "(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;", false);
        mv.visitInsn(Opcodes.POP);
        mv.visitInsn(Opcodes.RETURN);
        mv.visitMaxs(2, 1);
        mv.visitEnd();
        writer.visitEnd();
        return writer.toByteArray();
    }
}
