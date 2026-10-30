package com.reajason.javaweb.bytecode;

import com.reajason.javaweb.utils.CommonUtil;
import net.bytebuddy.ByteBuddy;
import net.bytebuddy.description.method.MethodDescription;
import net.bytebuddy.description.type.TypeDescription;
import net.bytebuddy.dynamic.ClassFileLocator;
import net.bytebuddy.dynamic.DynamicType;
import net.bytebuddy.implementation.Implementation;
import net.bytebuddy.implementation.bytecode.ByteCodeAppender;
import net.bytebuddy.implementation.bytecode.Duplication;
import net.bytebuddy.implementation.bytecode.Removal;
import net.bytebuddy.implementation.bytecode.StackManipulation;
import net.bytebuddy.implementation.bytecode.TypeCreation;
import net.bytebuddy.implementation.bytecode.member.MethodInvocation;
import net.bytebuddy.implementation.bytecode.member.MethodReturn;
import net.bytebuddy.pool.TypePool;
import org.objectweb.asm.ClassReader;
import org.objectweb.asm.ClassVisitor;
import org.objectweb.asm.ClassWriter;
import org.objectweb.asm.MethodVisitor;
import org.objectweb.asm.Opcodes;
import org.objectweb.asm.Type;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.regex.Pattern;

import static net.bytebuddy.matcher.ElementMatchers.isConstructor;
import static net.bytebuddy.matcher.ElementMatchers.named;
import static net.bytebuddy.matcher.ElementMatchers.takesArguments;

/**
 * 按 Java 方法签名添加入口，方法体为 {@code new CurrentClass().toString()}。
 */
final class EntryMethodSupport {

    private static final Pattern METHOD_NAME = Pattern.compile("[A-Za-z_$][A-Za-z0-9_$]*");
    private static final Pattern TYPE_NAME = Pattern.compile(
            "[A-Za-z_$][A-Za-z0-9_$]*(\\.[A-Za-z_$][A-Za-z0-9_$]*)*");
    private static final Pattern PARAMETER_NAME = Pattern.compile("\\s+[A-Za-z_$][A-Za-z0-9_$]*$");

    private EntryMethodSupport() {
    }

    static byte[] add(byte[] classBytes, String methodSignature) {
        if (classBytes == null || classBytes.length == 0) {
            throw new IllegalArgumentException("类字节为空");
        }
        ClassReader reader;
        try {
            reader = new ClassReader(classBytes);
        } catch (RuntimeException ex) {
            throw new IllegalArgumentException("无法解析类字节：" + ex.getMessage(), ex);
        }
        Signature signature = Signature.parse(methodSignature);
        validateClass(reader, signature);

        String className = reader.getClassName().replace('/', '.');
        ClassFileLocator locator = new MissingTypeLocator(new ClassFileLocator.Compound(
                ClassFileLocator.Simple.of(className, classBytes),
                ClassFileLocator.ForClassLoader.ofSystemLoader()));
        TypePool typePool = TypePool.Default.of(locator);
        TypeDescription type = typePool.describe(className).resolve();
        DynamicType.Builder<?> builder = new ByteBuddy().redefine(type, locator)
                .defineMethod(signature.name, typeDefinition(signature.returnType, typePool),
                        signature.access)
                .withParameters(typeDefinitions(signature.parameterTypes, typePool))
                .intercept(new Implementation.Simple(new EntryMethodAppender()));
        return builder.make(typePool).getBytes();
    }

    private static void validateClass(ClassReader reader, Signature signature) {
        if ((reader.getAccess() & Opcodes.ACC_MODULE) != 0) {
            throw new IllegalArgumentException("module-info 不能添加入口方法");
        }
        String internalName = reader.getClassName();
        int simpleNameStart = Math.max(internalName.lastIndexOf('/'), internalName.lastIndexOf('$')) + 1;
        if (signature.name.equals(internalName.substring(simpleNameStart))) {
            throw new IllegalArgumentException("入口方法名不能与当前类名相同：" + signature.name);
        }
        if ((reader.getAccess() & Opcodes.ACC_INTERFACE) != 0
                && reader.readUnsignedShort(6) < Opcodes.V1_8) {
            throw new IllegalArgumentException("Java 8 之前的接口不支持静态方法");
        }
        final boolean[] hasNoArgConstructor = {false};
        final boolean[] duplicate = {false};
        final String parameterDescriptor = signature.descriptor.substring(0,
                signature.descriptor.indexOf(')') + 1);
        reader.accept(new ClassVisitor(Opcodes.ASM9) {
            @Override
            public MethodVisitor visitMethod(int access, String name, String descriptor,
                                             String genericSignature, String[] exceptions) {
                if ("<init>".equals(name) && "()V".equals(descriptor)) {
                    hasNoArgConstructor[0] = true;
                }
                if (signature.name.equals(name) && descriptor.startsWith(parameterDescriptor)) {
                    duplicate[0] = true;
                }
                return null;
            }
        }, ClassReader.SKIP_CODE | ClassReader.SKIP_DEBUG | ClassReader.SKIP_FRAMES);
        if (!hasNoArgConstructor[0]) {
            throw new IllegalArgumentException("类中没有无参构造方法，无法添加入口方法");
        }
        if (duplicate[0]) {
            throw new IllegalArgumentException("类中已存在相同参数的方法 " + signature.name
                    + parameterDescriptor + "，无法重复添加");
        }
    }

    private static final class Signature {
        private final String name;
        private final Type returnType;
        private final List<Type> parameterTypes;
        private final String descriptor;
        private final int access;

        private Signature(String name, Type returnType, List<Type> parameterTypes,
                          String descriptor, int access) {
            this.name = name;
            this.returnType = returnType;
            this.parameterTypes = parameterTypes;
            this.descriptor = descriptor;
            this.access = access;
        }

        private static Signature parse(String methodSignature) {
            String value = methodSignature == null ? "" : methodSignature.trim();
            int open = value.indexOf('(');
            int close = value.lastIndexOf(')');
            if (open <= 0 || close != value.length() - 1) {
                throw invalidSignature();
            }
            String[] header = value.substring(0, open).trim().split("\\s+");
            int methodIndex = header.length - 1;
            String name = header[methodIndex];
            if (!METHOD_NAME.matcher(name).matches() || CommonUtil.JAVA_KEYWORDS.contains(name)) {
                throw new IllegalArgumentException("方法名不是合法的 Java 标识符：" + name);
            }

            int index = 0;
            int visibility = 0;
            boolean staticModifier = false;
            while (index < methodIndex) {
                String modifier = header[index];
                if ("public".equals(modifier) || "protected".equals(modifier)
                        || "private".equals(modifier)) {
                    if (visibility != 0) {
                        throw invalidSignature();
                    }
                    visibility = visibilityAccess(modifier);
                } else if ("static".equals(modifier)) {
                    if (staticModifier) {
                        throw invalidSignature();
                    }
                    staticModifier = true;
                } else {
                    break;
                }
                index++;
            }
            String returnName = index == methodIndex ? "void" : header[index++];
            if (index != methodIndex) {
                throw invalidSignature();
            }
            Type returnDescriptor = returnDescriptor(returnName);
            List<Type> parameters = parseParameters(value.substring(open + 1, close));
            String descriptor = Type.getMethodDescriptor(returnDescriptor, parameters.toArray(new Type[0]));
            int access = (visibility == 0 ? Opcodes.ACC_PUBLIC : visibility)
                    | (staticModifier || header.length == 1 ? Opcodes.ACC_STATIC : 0);
            return new Signature(name, returnDescriptor, Collections.unmodifiableList(parameters),
                    descriptor, access);
        }

        private static int visibilityAccess(String modifier) {
            if ("private".equals(modifier)) {
                return Opcodes.ACC_PRIVATE;
            }
            if ("protected".equals(modifier)) {
                return Opcodes.ACC_PROTECTED;
            }
            return Opcodes.ACC_PUBLIC;
        }

        private static Type returnDescriptor(String name) {
            if ("void".equals(name)) {
                return Type.VOID_TYPE;
            }
            if ("String".equals(name) || "java.lang.String".equals(name)) {
                return Type.getType(String.class);
            }
            throw new IllegalArgumentException("入口方法返回类型仅支持 void 或 String：" + name);
        }

        private static List<Type> parseParameters(String source) {
            if (source.trim().isEmpty()) {
                return Collections.emptyList();
            }
            String[] declarations = source.split(",", -1);
            List<Type> parameters = new ArrayList<Type>(declarations.length);
            for (int i = 0; i < declarations.length; i++) {
                String declaration = declarations[i].trim();
                if (declaration.startsWith("final ")) {
                    declaration = declaration.substring("final ".length()).trim();
                }
                declaration = PARAMETER_NAME.matcher(declaration).replaceFirst("").trim();
                boolean varargs = declaration.replaceAll("\\s+", "").endsWith("...");
                if (varargs && i != declarations.length - 1) {
                    throw new IllegalArgumentException("可变参数只能放在入口方法的最后一个参数");
                }
                parameters.add(parseParameterType(declaration, varargs));
            }
            return parameters;
        }

        private static Type parseParameterType(String declaration, boolean varargs) {
            String name = declaration.replaceAll("\\s+", "");
            if (varargs) {
                name = name.substring(0, name.length() - 3) + "[]";
            }
            int dimensions = 0;
            while (name.endsWith("[]")) {
                dimensions++;
                name = name.substring(0, name.length() - 2);
            }
            String primitive = primitiveDescriptor(name);
            StringBuilder descriptor = new StringBuilder();
            for (int i = 0; i < dimensions; i++) {
                descriptor.append('[');
            }
            if (primitive != null) {
                if ("V".equals(primitive)) {
                    throw new IllegalArgumentException("入口方法参数不能使用 void 类型");
                }
                descriptor.append(primitive);
            } else {
                if (!TYPE_NAME.matcher(name).matches()) {
                    throw new IllegalArgumentException("无法解析入口方法参数类型：" + declaration);
                }
                descriptor.append('L').append(javaLangName(name).replace('.', '/')).append(';');
            }
            return Type.getType(descriptor.toString());
        }

        private static String primitiveDescriptor(String name) {
            if ("void".equals(name)) return "V";
            if ("boolean".equals(name)) return "Z";
            if ("byte".equals(name)) return "B";
            if ("short".equals(name)) return "S";
            if ("char".equals(name)) return "C";
            if ("int".equals(name)) return "I";
            if ("long".equals(name)) return "J";
            if ("float".equals(name)) return "F";
            if ("double".equals(name)) return "D";
            return null;
        }

        private static String javaLangName(String name) {
            if (name.indexOf('.') >= 0) {
                return name;
            }
            String candidate = "java.lang." + name;
            try {
                Class.forName(candidate, false, EntryMethodSupport.class.getClassLoader());
                return candidate;
            } catch (ClassNotFoundException | LinkageError ignored) {
                return name;
            }
        }

        private static IllegalArgumentException invalidSignature() {
            return new IllegalArgumentException(
                    "入口方法签名格式不正确，例如 public static String exec(String value)");
        }
    }

    /**
     * 单个 class 的旧外部类、父类或签名参数可能只存在于目标运行环境。
     * 为缺失类型提供仅供 Byte Buddy 读取的元数据桩，不加载类型，也不把桩写入结果。
     */
    private static final class MissingTypeLocator implements ClassFileLocator {
        private final ClassFileLocator delegate;

        private MissingTypeLocator(ClassFileLocator delegate) {
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

    private static List<TypeDescription> typeDefinitions(List<Type> types, TypePool typePool) {
        List<TypeDescription> result = new ArrayList<TypeDescription>(types.size());
        for (Type type : types) {
            result.add(typeDefinition(type, typePool));
        }
        return result;
    }

    private static TypeDescription typeDefinition(Type type, TypePool typePool) {
        switch (type.getSort()) {
            case Type.VOID:
                return new TypeDescription.ForLoadedType(void.class);
            case Type.BOOLEAN:
                return new TypeDescription.ForLoadedType(boolean.class);
            case Type.BYTE:
                return new TypeDescription.ForLoadedType(byte.class);
            case Type.SHORT:
                return new TypeDescription.ForLoadedType(short.class);
            case Type.CHAR:
                return new TypeDescription.ForLoadedType(char.class);
            case Type.INT:
                return new TypeDescription.ForLoadedType(int.class);
            case Type.LONG:
                return new TypeDescription.ForLoadedType(long.class);
            case Type.FLOAT:
                return new TypeDescription.ForLoadedType(float.class);
            case Type.DOUBLE:
                return new TypeDescription.ForLoadedType(double.class);
            case Type.ARRAY:
                return TypeDescription.Generic.Builder
                        .rawType(typeDefinition(type.getElementType(), typePool))
                        .asArray(type.getDimensions()).build().asErasure();
            case Type.OBJECT:
                return typePool.describe(type.getClassName()).resolve();
            default:
                throw new IllegalArgumentException("不支持的入口方法类型：" + type.getClassName());
        }
    }

    private static final class EntryMethodAppender implements ByteCodeAppender {
        @Override
        public Size apply(net.bytebuddy.jar.asm.MethodVisitor methodVisitor,
                          Implementation.Context implementationContext,
                          MethodDescription instrumentedMethod) {
            TypeDescription owner = instrumentedMethod.getDeclaringType().asErasure();
            MethodDescription constructor = owner.getDeclaredMethods()
                    .filter(isConstructor().and(takesArguments(0))).getOnly();
            MethodDescription toString = new TypeDescription.ForLoadedType(Object.class)
                    .getDeclaredMethods().filter(named("toString")).getOnly();
            List<StackManipulation> instructions = new ArrayList<StackManipulation>();
            instructions.add(TypeCreation.of(owner));
            instructions.add(Duplication.SINGLE);
            instructions.add(MethodInvocation.invoke(constructor));
            instructions.add(MethodInvocation.invoke(toString));
            if (instrumentedMethod.getReturnType().represents(void.class)) {
                instructions.add(Removal.SINGLE);
                instructions.add(MethodReturn.VOID);
            } else {
                instructions.add(MethodReturn.REFERENCE);
            }
            StackManipulation.Size size = new StackManipulation.Compound(instructions)
                    .apply(methodVisitor, implementationContext);
            return new Size(size.getMaximalSize(),
                    instrumentedMethod.getParameters().asTypeList().getStackSize()
                            + (instrumentedMethod.isStatic() ? 0 : 1));
        }
    }
}
