package com.reajason.javaweb.bytecode;

import com.reajason.javaweb.utils.CommonUtil;
import org.objectweb.asm.ClassReader;
import org.objectweb.asm.ClassVisitor;
import org.objectweb.asm.ClassWriter;
import org.objectweb.asm.Label;
import org.objectweb.asm.MethodVisitor;
import org.objectweb.asm.Opcodes;
import org.objectweb.asm.Type;
import org.objectweb.asm.commons.ClassRemapper;
import org.objectweb.asm.commons.Remapper;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.regex.Pattern;

/**
 * 字节码小工具：把生成的类字节改写成不同利用场景需要的样子。
 *
 * <p>所有方法都是「类字节进、类字节出」的纯函数，不碰界面、不落文件、也不加载目标类。
 * 失败原因统一用中文 {@link IllegalArgumentException} 给出，界面直接展示。
 *
 * <ul>
 *   <li>{@link #changeClassInfo}：改父类（如 TemplatesImpl 用的 AbstractTranslet）、
 *       替换包名前缀（javax.servlet → jakarta.servlet）；</li>
 *   <li>{@link #addMainMethod}：添加 main/_main，调用自身构造方法，供
 *       {@code com.sun.org.apache.bcel.internal.util.JavaWrapper._main} 反射调用；</li>
 *   <li>{@link #addEntryMethod}：按签名添加成员/静态入口，调用自身无参构造与 toString；</li>
 *   <li>{@link #renameAndShrink}：类名随机化 + 清掉 SourceFile/行号/局部变量等溯源信息；</li>
 *   <li>{@link #addModuleBypass}：静态初始化时把当前类的 module 改成 java.base，绕过 JDK 9+ 模块限制；</li>
 *   <li>{@link #addStaticTrigger}：静态初始化时调用自身构造方法或 toString，
 *       配合 {@code Class.forName(name, true, loader)} 触发；</li>
 *   <li>{@link #convert}：不做改写，仅用于 Base64/GzipBase64 与 .class 互转。</li>
 * </ul>
 */
public class BytecodeToolService {

    private static final Pattern CLASS_NAME =
            Pattern.compile("[A-Za-z_$][A-Za-z0-9_$]*(/[A-Za-z_$][A-Za-z0-9_$]*)*");
    private static final Pattern METHOD_NAME =
            Pattern.compile("[A-Za-z_$][A-Za-z0-9_$]*");
    private static final String NO_ARG_CONSTRUCTOR = "()V";
    private static final String STRING_CONSTRUCTOR = "(Ljava/lang/String;)V";
    private static final Object[] EMPTY_FRAME = new Object[0];

    /**
     * 静态初始化触发的目标动作。
     */
    public enum TriggerMode {
        /** 实例化当前类后丢弃。 */
        CONSTRUCTOR,
        /** 实例化当前类并调用 toString，丢弃返回值。 */
        TO_STRING
    }

    /**
     * 构造方法调用方式；{@link #AUTO} 由具体工具决定优先项。
     */
    public enum ConstructorMode {
        /** 添加 main 时优先 String 构造（传 args[0]）；静态触发时优先无参构造。 */
        AUTO,
        NO_ARG,
        /** 调用 (String) 构造，参数取 main 的 args[0]；静态触发不支持。 */
        ARGS_FIRST,
        /** 调用 (String) 构造，参数使用用户输入的字面量。 */
        STRING_LITERAL
    }

    /**
     * 转换结果：改写后的类字节 + 解析出的类名。
     */
    public static final class TransformResult {

        private final byte[] classBytes;
        private final String className;

        private TransformResult(byte[] classBytes, String className) {
            this.classBytes = classBytes;
            this.className = className;
        }

        public byte[] getClassBytes() {
            return classBytes;
        }

        public String getClassName() {
            return className;
        }

        public int getSize() {
            return classBytes.length;
        }
    }

    /**
     * 不改写，只做一次类名解析（Base64/GzipBase64 ↔ .class 互转时用）。
     */
    public TransformResult convert(byte[] classBytes) {
        ClassReader reader = readerOf(classBytes);
        return new TransformResult(classBytes, binaryName(reader.getClassName()));
    }

    /**
     * 改父类 / 替换包名前缀；两个参数都可以留空，只做其中一项。
     *
     * @param newSuperClass 新父类的全限定名（点或斜杠分隔）；留空表示不改
     * @param relocateFrom  要替换的包名前缀（如 javax.servlet）；留空表示不替换
     * @param relocateTo    替换后的包名前缀（如 jakarta.servlet）
     */
    public TransformResult changeClassInfo(byte[] classBytes, String newSuperClass,
                                           String relocateFrom, String relocateTo) {
        byte[] result = classBytes;
        String from = trimToNull(relocateFrom);
        String to = trimToNull(relocateTo);
        if ((from == null) != (to == null)) {
            throw new IllegalArgumentException("包名替换需要同时填写原前缀与新前缀");
        }
        if (from != null) {
            result = relocateTypes(result, normalizeName(from, "原包名前缀"), normalizeName(to, "新包名前缀"));
        }
        String superClass = trimToNull(newSuperClass);
        if (superClass != null) {
            result = changeSuperClass(result, normalizeName(superClass, "父类"));
        }
        return convert(result);
    }

    /**
     * 添加 main / _main 方法：调用当前类自己的构造方法，供 JavaWrapper._main 之类的入口反射调用。
     *
     * @param methodName      方法名，留空默认 main
     * @param constructorMode 调哪个构造方法
     * @param literal         {@link ConstructorMode#STRING_LITERAL} 时的字符串参数
     */
    public TransformResult addMainMethod(byte[] classBytes, String methodName,
                                         ConstructorMode constructorMode, String literal) {
        ClassReader reader = readerOf(classBytes);
        String owner = reader.getClassName();
        String name = trimToNull(methodName);
        name = name == null ? "main" : name;
        if (!METHOD_NAME.matcher(name).matches() || CommonUtil.JAVA_KEYWORDS.contains(name)) {
            throw new IllegalArgumentException("方法名不是合法的 Java 标识符：" + name);
        }
        if ((reader.getAccess() & Opcodes.ACC_INTERFACE) != 0
                && reader.readUnsignedShort(6) < Opcodes.V1_8) {
            throw new IllegalArgumentException("Java 8 之前的接口不支持静态方法，无法添加 " + name);
        }
        if (methodExists(reader, name, "([Ljava/lang/String;)V")) {
            throw new IllegalArgumentException("类中已存在 " + name + "(String[]) 方法，无法重复添加");
        }
        ResolvedConstructor constructor = resolveConstructor(reader, owner, constructorMode, literal, true);

        ClassWriter writer = new ClassWriter(reader, 0);
        reader.accept(new ClassVisitor(Opcodes.ASM9, writer) {
        }, 0);

        MethodVisitor mv = writer.visitMethod(Opcodes.ACC_PUBLIC | Opcodes.ACC_STATIC,
                name, "([Ljava/lang/String;)V", null, new String[]{"java/lang/Throwable"});
        mv.visitCode();
        emitNewInstance(mv, owner, constructor);
        mv.visitInsn(Opcodes.POP);
        mv.visitInsn(Opcodes.RETURN);
        mv.visitMaxs(constructor.maxStack, 1);
        mv.visitEnd();
        return convert(writer.toByteArray());
    }

    /**
     * 按 Java 方法签名添加入口，调用当前类的无参构造与 toString。
     * 支持 public/protected/private；static 修饰符决定成员/静态方法。
     * 仅写方法名和参数的简写默认为 public static void；当前支持 void/String 返回类型。
     *
     * @param methodSignature 例如 {@code public static String exec(String value)}
     *                        或 {@code _main(String[] args)}
     */
    public TransformResult addEntryMethod(byte[] classBytes, String methodSignature) {
        return convert(EntryMethodSupport.add(classBytes, methodSignature));
    }

    /**
     * 随机类名 + 字节码瘦身。
     *
     * @param newClassName  新类名：简单类名或全限定名；留空保持原名
     * @param newPackageName 新包名：留空保持原包名；与 {@code newClassName} 同时给全限定名时冲突
     * @param randomName    随机生成完整类名（忽略 {@code newClassName}；显式包名仍优先）
     * @param stripDebug    清掉 SourceFile / 行号 / 局部变量等调试信息
     */
    public TransformResult renameAndShrink(byte[] classBytes, String newClassName, String newPackageName,
                                           boolean randomName, boolean stripDebug) {
        ClassReader reader = readerOf(classBytes);
        String oldName = reader.getClassName();
        String newName = resolveNewClassName(oldName, newClassName, newPackageName, randomName);
        if (newName.equals(oldName) && !stripDebug) {
            return convert(classBytes);
        }
        final String oldInternal = oldName;
        final String newInternal = newName;
        final String newSourceFile = simpleNameOf(newInternal) + ".java";

        ClassWriter writer = new ClassWriter(0);
        ClassVisitor sink = new ClassVisitor(Opcodes.ASM9, writer) {
            @Override
            public void visitSource(String source, String debug) {
                if (!stripDebug) {
                    super.visitSource(newSourceFile, null);
                }
            }
        };
        Remapper remapper = new Remapper(Opcodes.ASM9) {
            @Override
            public String map(String internalName) {
                if (oldInternal.equals(internalName)) {
                    return newInternal;
                }
                // 内部类/匿名类是随主类一起改名的：Outer$1 -> Renamed$1
                if (internalName.startsWith(oldInternal + "$")) {
                    return newInternal + internalName.substring(oldInternal.length());
                }
                return internalName;
            }
        };
        reader.accept(new ClassRemapper(sink, remapper), stripDebug ? ClassReader.SKIP_DEBUG : 0);
        return convert(writer.toByteArray());
    }

    /**
     * 在静态初始化里加入 JDK 9+ 模块限制绕过：把当前类的 module 改成 java.base，
     * 之后反射访问 JDK 内部类不再受模块系统限制。JDK 8 上这段代码会被静默跳过。
     */
    public TransformResult addModuleBypass(byte[] classBytes) {
        ClassReader reader = readerOf(classBytes);
        String owner = reader.getClassName();
        int classAccess = reader.getAccess();
        int classVersion = reader.readUnsignedShort(6);
        if ((classAccess & Opcodes.ACC_MODULE) != 0) {
            throw new IllegalArgumentException("module-info 不能添加静态初始化代码");
        }
        boolean isInterface = (classAccess & Opcodes.ACC_INTERFACE) != 0;
        if (isInterface && classVersion < Opcodes.V1_8) {
            throw new IllegalArgumentException("Java 8 之前的接口不支持静态方法，无法注入模块绕过代码");
        }
        boolean emitFrames = classVersion >= Opcodes.V1_6;
        Set<String> methodNames = methodNames(reader);
        String token = CommonUtil.getRandomString(6);
        String workName = uniqueMethodName("$msp$w" + token, methodNames);
        String guardName = uniqueMethodName("$msp$g" + token, methodNames);
        // Java 8 的接口只允许 public static 方法，private static 要 Java 9（class version 53）
        final int helperAccess = (isInterface ? Opcodes.ACC_PUBLIC : Opcodes.ACC_PRIVATE)
                | Opcodes.ACC_STATIC | Opcodes.ACC_SYNTHETIC;

        ClassWriter writer = new ClassWriter(reader, 0);
        final boolean[] clinitSeen = {false};
        reader.accept(new ClassVisitor(Opcodes.ASM9, writer) {
            @Override
            public MethodVisitor visitMethod(int access, String name, String descriptor,
                                             String signature, String[] exceptions) {
                MethodVisitor mv = super.visitMethod(access, name, descriptor, signature, exceptions);
                if (!"<clinit>".equals(name) || !NO_ARG_CONSTRUCTOR.equals(descriptor)) {
                    return mv;
                }
                clinitSeen[0] = true;
                return new MethodVisitor(Opcodes.ASM9, mv) {
                    @Override
                    public void visitCode() {
                        super.visitCode();
                        // 空参数、void 返回的静态调用不改变操作数栈，原有 StackMapTable 仍然有效
                        mv.visitMethodInsn(Opcodes.INVOKESTATIC, owner, guardName, NO_ARG_CONSTRUCTOR, false);
                    }
                };
            }

            @Override
            public void visitEnd() {
                if (!clinitSeen[0]) {
                    MethodVisitor clinit = super.visitMethod(Opcodes.ACC_STATIC, "<clinit>",
                            NO_ARG_CONSTRUCTOR, null, null);
                    clinit.visitCode();
                    clinit.visitMethodInsn(Opcodes.INVOKESTATIC, owner, guardName, NO_ARG_CONSTRUCTOR, false);
                    clinit.visitInsn(Opcodes.RETURN);
                    clinit.visitMaxs(0, 0);
                    clinit.visitEnd();
                }
                emitModuleBypassWork(super.visitMethod(helperAccess, workName,
                        NO_ARG_CONSTRUCTOR, null, null), owner);
                emitModuleBypassGuard(super.visitMethod(helperAccess, guardName,
                                NO_ARG_CONSTRUCTOR, null, new String[]{"java/lang/Throwable"}),
                        owner, workName, emitFrames);
                super.visitEnd();
            }
        }, 0);
        return convert(writer.toByteArray());
    }

    /**
     * 在静态初始化里调用当前类的构造方法或 toString。
     *
     * <p>注意：构造方法参数为 String 时，静态块发生在类初始化阶段，无法拿到外部参数，
     * 所以 {@link ConstructorMode#AUTO} 会优先选无参构造；没有无参构造才退化为空字符串。
     */
    public TransformResult addStaticTrigger(byte[] classBytes, TriggerMode triggerMode,
                                            ConstructorMode constructorMode, String literal) {
        ClassReader reader = readerOf(classBytes);
        String owner = reader.getClassName();
        ResolvedConstructor constructor = resolveConstructor(reader, owner,
                constructorMode == ConstructorMode.ARGS_FIRST ? ConstructorMode.STRING_LITERAL : constructorMode,
                literal, false);
        final TriggerMode mode = triggerMode == null ? TriggerMode.CONSTRUCTOR : triggerMode;

        ClassWriter writer = new ClassWriter(reader, 0);
        final boolean[] clinitSeen = {false};
        reader.accept(new ClassVisitor(Opcodes.ASM9, writer) {
            @Override
            public MethodVisitor visitMethod(int access, String name, String descriptor,
                                             String signature, String[] exceptions) {
                MethodVisitor mv = super.visitMethod(access, name, descriptor, signature, exceptions);
                if (!"<clinit>".equals(name) || !NO_ARG_CONSTRUCTOR.equals(descriptor)) {
                    return mv;
                }
                clinitSeen[0] = true;
                return new MethodVisitor(Opcodes.ASM9, mv) {
                    @Override
                    public void visitCode() {
                        super.visitCode();
                        emitStaticTrigger(mv, owner, constructor, mode);
                    }

                    @Override
                    public void visitMaxs(int maxStack, int maxLocals) {
                        mv.visitMaxs(Math.max(maxStack, constructor.maxStack), maxLocals);
                    }
                };
            }

            @Override
            public void visitEnd() {
                if (!clinitSeen[0]) {
                    MethodVisitor clinit = super.visitMethod(Opcodes.ACC_STATIC, "<clinit>",
                            NO_ARG_CONSTRUCTOR, null, null);
                    clinit.visitCode();
                    emitStaticTrigger(clinit, owner, constructor, mode);
                    clinit.visitInsn(Opcodes.RETURN);
                    clinit.visitMaxs(constructor.maxStack, 0);
                    clinit.visitEnd();
                }
                super.visitEnd();
            }
        }, 0);
        return convert(writer.toByteArray());
    }

    // ------------------------------------------------------------------------------------
    // 包名替换 / 父类修改
    // ------------------------------------------------------------------------------------

    private static byte[] relocateTypes(byte[] classBytes, final String from, final String to) {
        if (from.equals(to)) {
            return classBytes;
        }
        ClassReader reader = readerOf(classBytes);
        ClassWriter writer = new ClassWriter(reader, 0);
        Remapper remapper = new Remapper(Opcodes.ASM9) {
            @Override
            public String map(String internalName) {
                if (internalName.equals(from)) {
                    return to;
                }
                if (internalName.startsWith(from + "/")) {
                    return to + internalName.substring(from.length());
                }
                return internalName;
            }
        };
        reader.accept(new ClassRemapper(writer, remapper), 0);
        return writer.toByteArray();
    }

    private static byte[] changeSuperClass(byte[] classBytes, String newSuperClass) {
        ClassReader reader = readerOf(classBytes);
        final String oldSuper = reader.getSuperName();
        if (oldSuper == null) {
            throw new IllegalArgumentException("不是普通类（module-info 等），无法修改父类");
        }
        if (newSuperClass.equals(oldSuper)) {
            return classBytes;
        }
        ClassWriter writer = new ClassWriter(reader, 0);
        reader.accept(new ClassVisitor(Opcodes.ASM9, writer) {
            @Override
            public void visit(int version, int access, String name, String signature,
                              String superName, String[] interfaces) {
                if ((access & Opcodes.ACC_INTERFACE) != 0) {
                    throw new IllegalArgumentException("接口不能修改父类");
                }
                super.visit(version, access, name, signature, newSuperClass, interfaces);
            }

            @Override
            public MethodVisitor visitMethod(int access, String name, String descriptor,
                                             String signature, String[] exceptions) {
                MethodVisitor mv = super.visitMethod(access, name, descriptor, signature, exceptions);
                if (!"<init>".equals(name)) {
                    return mv;
                }
                return new MethodVisitor(Opcodes.ASM9, mv) {
                    @Override
                    public void visitMethodInsn(int opcode, String owner, String name,
                                                String descriptor, boolean isInterface) {
                        if (opcode == Opcodes.INVOKESPECIAL && "<init>".equals(name)
                                && oldSuper.equals(owner)) {
                            // 构造方法里的 super() 跟着改到新父类，描述符保持不变：
                            // 新父类没有同签名构造方法时会在加载阶段报错，这里不阻止（工具类无法可靠解析目标父类）
                            mv.visitMethodInsn(opcode, newSuperClass, name, descriptor, isInterface);
                        } else {
                            mv.visitMethodInsn(opcode, owner, name, descriptor, isInterface);
                        }
                    }
                };
            }
        }, 0);
        return writer.toByteArray();
    }

    // ------------------------------------------------------------------------------------
    // 构造方法调用代码
    // ------------------------------------------------------------------------------------

    private static final class ResolvedConstructor {
        private final ConstructorMode mode;
        private final String literal;
        private final int maxStack;

        private ResolvedConstructor(ConstructorMode mode, String literal) {
            this.mode = mode;
            this.literal = literal;
            // NEW + DUP + 参数（有参时 ALOAD/ICONST/AALOAD 或 LDC）最多占 4 格
            this.maxStack = mode == ConstructorMode.NO_ARG ? 2 : 4;
        }
    }

    private static ResolvedConstructor resolveConstructor(ClassReader reader, String owner,
                                                          ConstructorMode mode, String literal,
                                                          boolean preferStringArgsFirst) {
        List<String> constructors = constructorDescriptors(reader);
        boolean hasNoArg = constructors.contains(NO_ARG_CONSTRUCTOR);
        boolean hasString = constructors.contains(STRING_CONSTRUCTOR);
        ConstructorMode requested = mode == null ? ConstructorMode.AUTO : mode;
        switch (requested) {
            case AUTO:
                if (preferStringArgsFirst && hasString) {
                    return new ResolvedConstructor(ConstructorMode.ARGS_FIRST, null);
                }
                if (!preferStringArgsFirst && hasNoArg) {
                    return new ResolvedConstructor(ConstructorMode.NO_ARG, null);
                }
                if (hasString) {
                    return new ResolvedConstructor(ConstructorMode.STRING_LITERAL, literal == null ? "" : literal);
                }
                if (hasNoArg) {
                    return new ResolvedConstructor(ConstructorMode.NO_ARG, null);
                }
                throw noUsableConstructor(owner, constructors);
            case NO_ARG:
                if (!hasNoArg) {
                    throw new IllegalArgumentException("类中没有无参构造方法：" + owner
                            + "，可用构造方法：" + describe(constructors));
                }
                return new ResolvedConstructor(ConstructorMode.NO_ARG, null);
            case ARGS_FIRST:
                if (!hasString) {
                    throw new IllegalArgumentException("类中没有 (String) 构造方法：" + owner
                            + "，可用构造方法：" + describe(constructors));
                }
                return new ResolvedConstructor(ConstructorMode.ARGS_FIRST, null);
            case STRING_LITERAL:
            default:
                if (!hasString) {
                    throw new IllegalArgumentException("类中没有 (String) 构造方法：" + owner
                            + "，可用构造方法：" + describe(constructors));
                }
                return new ResolvedConstructor(ConstructorMode.STRING_LITERAL, literal == null ? "" : literal);
        }
    }

    private static IllegalArgumentException noUsableConstructor(String owner, List<String> constructors) {
        return new IllegalArgumentException("类中没有可用的无参/(String) 构造方法：" + owner
                + "，可用构造方法：" + describe(constructors));
    }

    private static void emitNewInstance(MethodVisitor mv, String owner, ResolvedConstructor constructor) {
        mv.visitTypeInsn(Opcodes.NEW, owner);
        mv.visitInsn(Opcodes.DUP);
        if (constructor.mode == ConstructorMode.ARGS_FIRST) {
            mv.visitVarInsn(Opcodes.ALOAD, 0);
            mv.visitInsn(Opcodes.ICONST_0);
            mv.visitInsn(Opcodes.AALOAD);
            mv.visitMethodInsn(Opcodes.INVOKESPECIAL, owner, "<init>", STRING_CONSTRUCTOR, false);
        } else if (constructor.mode == ConstructorMode.STRING_LITERAL) {
            mv.visitLdcInsn(constructor.literal);
            mv.visitMethodInsn(Opcodes.INVOKESPECIAL, owner, "<init>", STRING_CONSTRUCTOR, false);
        } else {
            mv.visitMethodInsn(Opcodes.INVOKESPECIAL, owner, "<init>", NO_ARG_CONSTRUCTOR, false);
        }
    }

    private static void emitStaticTrigger(MethodVisitor mv, String owner,
                                          ResolvedConstructor constructor, TriggerMode mode) {
        emitNewInstance(mv, owner, constructor);
        if (mode == TriggerMode.TO_STRING) {
            mv.visitMethodInsn(Opcodes.INVOKEVIRTUAL, owner, "toString", "()Ljava/lang/String;", false);
        }
        mv.visitInsn(Opcodes.POP);
    }

    // ------------------------------------------------------------------------------------
    // 模块绕过代码
    // ------------------------------------------------------------------------------------

    /**
     * 生成绕过代码本体。逻辑与 core 的 ByPassJavaModuleInterceptor 一致：
     * 通过 Unsafe 把当前类的 Class.module 改成 java.base 的 Module。
     * 这段代码不自己捕获异常，由 {@link #emitModuleBypassGuard} 包一层 try/catch。
     */
    private static void emitModuleBypassWork(MethodVisitor mv, String owner) {
        mv.visitCode();
        // Class<?> unsafeClass = Class.forName("sun.misc.Unsafe");
        mv.visitLdcInsn("sun.misc.Unsafe");
        mv.visitMethodInsn(Opcodes.INVOKESTATIC, "java/lang/Class", "forName",
                "(Ljava/lang/String;)Ljava/lang/Class;", false);
        mv.visitVarInsn(Opcodes.ASTORE, 0);
        // Field unsafeField = unsafeClass.getDeclaredField("theUnsafe");
        mv.visitVarInsn(Opcodes.ALOAD, 0);
        mv.visitLdcInsn("theUnsafe");
        mv.visitMethodInsn(Opcodes.INVOKEVIRTUAL, "java/lang/Class", "getDeclaredField",
                "(Ljava/lang/String;)Ljava/lang/reflect/Field;", false);
        mv.visitVarInsn(Opcodes.ASTORE, 1);
        // unsafeField.setAccessible(true);
        mv.visitVarInsn(Opcodes.ALOAD, 1);
        mv.visitInsn(Opcodes.ICONST_1);
        mv.visitMethodInsn(Opcodes.INVOKEVIRTUAL, "java/lang/reflect/Field", "setAccessible", "(Z)V", false);
        // Object unsafe = unsafeField.get(null);
        mv.visitVarInsn(Opcodes.ALOAD, 1);
        mv.visitInsn(Opcodes.ACONST_NULL);
        mv.visitMethodInsn(Opcodes.INVOKEVIRTUAL, "java/lang/reflect/Field", "get",
                "(Ljava/lang/Object;)Ljava/lang/Object;", false);
        mv.visitVarInsn(Opcodes.ASTORE, 2);
        // Object module = Class.class.getMethod("getModule").invoke(Object.class, (Object[]) null);
        mv.visitLdcInsn(Type.getType(Class.class));
        mv.visitLdcInsn("getModule");
        mv.visitInsn(Opcodes.ICONST_0);
        mv.visitTypeInsn(Opcodes.ANEWARRAY, "java/lang/Class");
        mv.visitMethodInsn(Opcodes.INVOKEVIRTUAL, "java/lang/Class", "getMethod",
                "(Ljava/lang/String;[Ljava/lang/Class;)Ljava/lang/reflect/Method;", false);
        mv.visitLdcInsn(Type.getType(Object.class));
        mv.visitInsn(Opcodes.ACONST_NULL);
        mv.visitMethodInsn(Opcodes.INVOKEVIRTUAL, "java/lang/reflect/Method", "invoke",
                "(Ljava/lang/Object;[Ljava/lang/Object;)Ljava/lang/Object;", false);
        mv.visitVarInsn(Opcodes.ASTORE, 3);
        // Method objectFieldOffset = unsafeClass.getMethod("objectFieldOffset", Field.class);
        mv.visitVarInsn(Opcodes.ALOAD, 0);
        mv.visitLdcInsn("objectFieldOffset");
        mv.visitInsn(Opcodes.ICONST_1);
        mv.visitTypeInsn(Opcodes.ANEWARRAY, "java/lang/Class");
        mv.visitInsn(Opcodes.DUP);
        mv.visitInsn(Opcodes.ICONST_0);
        mv.visitLdcInsn(Type.getType(java.lang.reflect.Field.class));
        mv.visitInsn(Opcodes.AASTORE);
        mv.visitMethodInsn(Opcodes.INVOKEVIRTUAL, "java/lang/Class", "getMethod",
                "(Ljava/lang/String;[Ljava/lang/Class;)Ljava/lang/reflect/Method;", false);
        mv.visitVarInsn(Opcodes.ASTORE, 4);
        // Field moduleField = Class.class.getDeclaredField("module");
        mv.visitLdcInsn(Type.getType(Class.class));
        mv.visitLdcInsn("module");
        mv.visitMethodInsn(Opcodes.INVOKEVIRTUAL, "java/lang/Class", "getDeclaredField",
                "(Ljava/lang/String;)Ljava/lang/reflect/Field;", false);
        mv.visitVarInsn(Opcodes.ASTORE, 5);
        // long offset = ((Long) objectFieldOffset.invoke(unsafe, moduleField)).longValue();
        mv.visitVarInsn(Opcodes.ALOAD, 4);
        mv.visitVarInsn(Opcodes.ALOAD, 2);
        mv.visitInsn(Opcodes.ICONST_1);
        mv.visitTypeInsn(Opcodes.ANEWARRAY, "java/lang/Object");
        mv.visitInsn(Opcodes.DUP);
        mv.visitInsn(Opcodes.ICONST_0);
        mv.visitVarInsn(Opcodes.ALOAD, 5);
        mv.visitInsn(Opcodes.AASTORE);
        mv.visitMethodInsn(Opcodes.INVOKEVIRTUAL, "java/lang/reflect/Method", "invoke",
                "(Ljava/lang/Object;[Ljava/lang/Object;)Ljava/lang/Object;", false);
        mv.visitTypeInsn(Opcodes.CHECKCAST, "java/lang/Long");
        mv.visitMethodInsn(Opcodes.INVOKEVIRTUAL, "java/lang/Long", "longValue", "()J", false);
        mv.visitVarInsn(Opcodes.LSTORE, 6);
        // Method getAndSetObject = unsafeClass.getMethod("getAndSetObject", Object.class, long.class, Object.class);
        mv.visitVarInsn(Opcodes.ALOAD, 0);
        mv.visitLdcInsn("getAndSetObject");
        mv.visitInsn(Opcodes.ICONST_3);
        mv.visitTypeInsn(Opcodes.ANEWARRAY, "java/lang/Class");
        mv.visitInsn(Opcodes.DUP);
        mv.visitInsn(Opcodes.ICONST_0);
        mv.visitLdcInsn(Type.getType(Object.class));
        mv.visitInsn(Opcodes.AASTORE);
        mv.visitInsn(Opcodes.DUP);
        mv.visitInsn(Opcodes.ICONST_1);
        // long.class 不能用 LDC（常量池里的 "J" 会被当成类名加载），要读 Long.TYPE
        mv.visitFieldInsn(Opcodes.GETSTATIC, "java/lang/Long", "TYPE", "Ljava/lang/Class;");
        mv.visitInsn(Opcodes.AASTORE);
        mv.visitInsn(Opcodes.DUP);
        mv.visitInsn(Opcodes.ICONST_2);
        mv.visitLdcInsn(Type.getType(Object.class));
        mv.visitInsn(Opcodes.AASTORE);
        mv.visitMethodInsn(Opcodes.INVOKEVIRTUAL, "java/lang/Class", "getMethod",
                "(Ljava/lang/String;[Ljava/lang/Class;)Ljava/lang/reflect/Method;", false);
        mv.visitVarInsn(Opcodes.ASTORE, 8);
        // getAndSetObject.invoke(unsafe, CurrentClass.class, offset, module);
        mv.visitVarInsn(Opcodes.ALOAD, 8);
        mv.visitVarInsn(Opcodes.ALOAD, 2);
        mv.visitInsn(Opcodes.ICONST_3);
        mv.visitTypeInsn(Opcodes.ANEWARRAY, "java/lang/Object");
        mv.visitInsn(Opcodes.DUP);
        mv.visitInsn(Opcodes.ICONST_0);
        mv.visitLdcInsn(Type.getType("L" + owner + ";"));
        mv.visitInsn(Opcodes.AASTORE);
        mv.visitInsn(Opcodes.DUP);
        mv.visitInsn(Opcodes.ICONST_1);
        mv.visitVarInsn(Opcodes.LLOAD, 6);
        mv.visitMethodInsn(Opcodes.INVOKESTATIC, "java/lang/Long", "valueOf",
                "(J)Ljava/lang/Long;", false);
        mv.visitInsn(Opcodes.AASTORE);
        mv.visitInsn(Opcodes.DUP);
        mv.visitInsn(Opcodes.ICONST_2);
        mv.visitVarInsn(Opcodes.ALOAD, 3);
        mv.visitInsn(Opcodes.AASTORE);
        mv.visitMethodInsn(Opcodes.INVOKEVIRTUAL, "java/lang/reflect/Method", "invoke",
                "(Ljava/lang/Object;[Ljava/lang/Object;)Ljava/lang/Object;", false);
        mv.visitInsn(Opcodes.POP);
        mv.visitInsn(Opcodes.RETURN);
        mv.visitMaxs(8, 9);
        mv.visitEnd();
    }

    /**
     * try { work(); } catch (Throwable ignored) {} —— 自身不用局部变量，
     * 所以 handler 的帧只有操作数栈上的 Throwable，可手工写出，不依赖 COMPUTE_FRAMES。
     */
    private static void emitModuleBypassGuard(MethodVisitor mv, String owner, String workName,
                                              boolean emitFrames) {
        mv.visitCode();
        Label start = new Label();
        Label end = new Label();
        Label handler = new Label();
        Label done = new Label();
        mv.visitTryCatchBlock(start, end, handler, "java/lang/Throwable");
        mv.visitLabel(start);
        mv.visitMethodInsn(Opcodes.INVOKESTATIC, owner, workName, NO_ARG_CONSTRUCTOR, false);
        mv.visitLabel(end);
        mv.visitJumpInsn(Opcodes.GOTO, done);
        mv.visitLabel(handler);
        if (emitFrames) {
            mv.visitFrame(Opcodes.F_FULL, 0, EMPTY_FRAME, 1, new Object[]{"java/lang/Throwable"});
        }
        mv.visitInsn(Opcodes.POP);
        mv.visitLabel(done);
        if (emitFrames) {
            mv.visitFrame(Opcodes.F_FULL, 0, EMPTY_FRAME, 0, EMPTY_FRAME);
        }
        mv.visitInsn(Opcodes.RETURN);
        mv.visitMaxs(1, 0);
        mv.visitEnd();
    }

    // ------------------------------------------------------------------------------------
    // 类名 / 方法名 / 读取工具
    // ------------------------------------------------------------------------------------

    private static ClassReader readerOf(byte[] classBytes) {
        if (classBytes == null || classBytes.length == 0) {
            throw new IllegalArgumentException("类字节为空");
        }
        try {
            return new ClassReader(classBytes);
        } catch (RuntimeException ex) {
            throw new IllegalArgumentException("无法解析类字节：" + messageOf(ex));
        }
    }

    private static String resolveNewClassName(String oldName, String newClassName,
                                              String newPackageName, boolean randomName) {
        String specified = trimToNull(newClassName);
        String packageName = trimToNull(newPackageName);
        String targetPackage = packageName == null ? null : normalizeName(packageName, "包名");
        if (randomName) {
            String randomNameInternal = CommonUtil.generateInjectorClassName().replace('.', '/');
            return targetPackage == null
                    ? randomNameInternal
                    : join(targetPackage, simpleNameOf(randomNameInternal));
        }
        if (specified == null) {
            if (targetPackage == null) {
                return oldName;
            }
            return join(targetPackage, simpleNameOf(oldName));
        }
        String internal = normalizeName(specified, "类名");
        if (internal.indexOf('/') >= 0) {
            if (targetPackage != null) {
                throw new IllegalArgumentException("类名已包含包名，请留空包名字段");
            }
            return internal;
        }
        return join(targetPackage == null ? packageOf(oldName) : targetPackage, internal);
    }

    private static String normalizeName(String name, String label) {
        String internal = name.trim().replace('.', '/');
        if (!CLASS_NAME.matcher(internal).matches()) {
            throw new IllegalArgumentException(label + "不是合法的类名/包名：" + name);
        }
        return internal;
    }

    private static String join(String packageName, String simpleName) {
        return packageName == null || packageName.isEmpty() ? simpleName : packageName + "/" + simpleName;
    }

    private static String packageOf(String internalName) {
        int index = internalName.lastIndexOf('/');
        return index < 0 ? "" : internalName.substring(0, index);
    }

    private static String simpleNameOf(String internalName) {
        int index = internalName.lastIndexOf('/');
        return index < 0 ? internalName : internalName.substring(index + 1);
    }

    private static String binaryName(String internalName) {
        return internalName.replace('/', '.');
    }

    private static String trimToNull(String value) {
        if (value == null) {
            return null;
        }
        String trimmed = value.trim();
        return trimmed.isEmpty() ? null : trimmed;
    }

    private static String messageOf(Throwable ex) {
        return ex.getMessage() == null ? ex.getClass().getSimpleName() : ex.getMessage();
    }

    private static Set<String> methodNames(ClassReader reader) {
        final Set<String> names = new HashSet<String>();
        reader.accept(new ClassVisitor(Opcodes.ASM9) {
            @Override
            public MethodVisitor visitMethod(int access, String name, String descriptor,
                                             String signature, String[] exceptions) {
                names.add(name);
                return null;
            }
        }, ClassReader.SKIP_CODE | ClassReader.SKIP_DEBUG | ClassReader.SKIP_FRAMES);
        return names;
    }

    private static List<String> constructorDescriptors(ClassReader reader) {
        final List<String> descriptors = new ArrayList<String>();
        reader.accept(new ClassVisitor(Opcodes.ASM9) {
            @Override
            public MethodVisitor visitMethod(int access, String name, String descriptor,
                                             String signature, String[] exceptions) {
                if ("<init>".equals(name)) {
                    descriptors.add(descriptor);
                }
                return null;
            }
        }, ClassReader.SKIP_CODE | ClassReader.SKIP_DEBUG | ClassReader.SKIP_FRAMES);
        return descriptors;
    }

    private static boolean methodExists(ClassReader reader, final String methodName,
                                        final String descriptor) {
        final boolean[] found = {false};
        reader.accept(new ClassVisitor(Opcodes.ASM9) {
            @Override
            public MethodVisitor visitMethod(int access, String name, String methodDescriptor,
                                             String signature, String[] exceptions) {
                if (methodName.equals(name) && descriptor.equals(methodDescriptor)) {
                    found[0] = true;
                }
                return null;
            }
        }, ClassReader.SKIP_CODE | ClassReader.SKIP_DEBUG | ClassReader.SKIP_FRAMES);
        return found[0];
    }

    private static String uniqueMethodName(String candidate, Set<String> existing) {
        String name = candidate;
        while (existing.contains(name)) {
            name = name + "x";
        }
        return name;
    }

    private static String describe(List<String> constructors) {
        return constructors.isEmpty() ? "(无)" : constructors.toString();
    }
}
