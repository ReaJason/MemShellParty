package com.reajason.javaweb.boot.service;

import com.reajason.javaweb.ClassBytesShrink;
import com.reajason.javaweb.asm.ClassBytesDecoder;
import com.reajason.javaweb.asm.ClassBytesEncoder;
import com.reajason.javaweb.asm.ClassInitializer;
import com.reajason.javaweb.asm.ClassNameParser;
import com.reajason.javaweb.asm.ClassRenameUtils;
import com.reajason.javaweb.boot.dto.BytecodeClassResponse;
import com.reajason.javaweb.boot.dto.BytecodeTransformRequest;
import com.reajason.javaweb.boot.dto.BytecodeTransformResponse;
import com.reajason.javaweb.buddy.ByPassJavaModuleInterceptor;
import com.reajason.javaweb.buddy.ClassRenameVisitorWrapper;
import com.reajason.javaweb.buddy.EntryMethodBuilder;
import com.reajason.javaweb.buddy.MissingTypeLocator;
import com.reajason.javaweb.buddy.StaticBlockSelfConstructorCall;
import com.reajason.javaweb.memshell.PackerRegistry;
import com.reajason.javaweb.memshell.config.ObfuscationConfig;
import com.reajason.javaweb.memshell.obfuscation.ClassObfuscation;
import com.reajason.javaweb.memshell.obfuscation.MethodContracts;
import com.reajason.javaweb.memshell.obfuscation.ObfuscationTarget;
import com.reajason.javaweb.packer.ClassPackerConfig;
import com.reajason.javaweb.packer.PackerConstraints;
import com.reajason.javaweb.probe.config.ProbeConfig;
import com.reajason.javaweb.probe.generator.response.ResponseGenerator;
import com.reajason.javaweb.utils.CommonUtil;
import net.bytebuddy.ByteBuddy;
import net.bytebuddy.description.type.TypeDescription;
import net.bytebuddy.dynamic.ClassFileLocator;
import net.bytebuddy.dynamic.DynamicType;
import net.bytebuddy.pool.TypePool;
import org.objectweb.asm.ClassReader;
import org.objectweb.asm.ClassVisitor;
import org.objectweb.asm.MethodVisitor;
import org.objectweb.asm.Opcodes;
import org.springframework.stereotype.Service;

import java.util.Collections;
import java.util.regex.Pattern;

@Service
public class BytecodeTransformService {

    private static final Pattern CLASS_NAME =
            Pattern.compile("[A-Za-z_$][A-Za-z0-9_$]*(\\.[A-Za-z_$][A-Za-z0-9_$]*)*");
    private static final String NO_ARG_CONSTRUCTOR = "()V";

    private final ClassBytesDecoder decoder = new ClassBytesDecoder();
    private final ClassNameParser classNameParser = new ClassNameParser();

    public BytecodeClassResponse decode(String base64Text) {
        ClassBytesDecoder.DecodedClass decoded = decoder.decodeBase64(base64Text);
        return new BytecodeClassResponse(decoded.getClassName(), decoded.getClassBytes().length,
                ClassBytesEncoder.encode(decoded.getClassBytes(), false));
    }

    public BytecodeTransformResponse transform(BytecodeTransformRequest request) {
        if (request == null) {
            throw new IllegalArgumentException("请求不能为空");
        }
        PackerConstraints constraints = PackerConstraints.forPacker(request.getPacker());
        constraints.constrainObfuscation(request.getObfuscation());
        if (request.getProbe() != null) {
            constraints.constrainObfuscation(request.getProbe().getObfuscation());
        }
        byte[] classBytes = applyTools(decoder.decodeBase64(request.getClassBytesBase64()).getClassBytes(),
                request);
        String className = classNameParser.parseClassName(classBytes);
        String requiredClassName = constraints.enforceClassName(className);
        if (!requiredClassName.equals(className)) {
            classBytes = redefine(classBytes, className, requiredClassName, false, false);
            className = classNameParser.parseClassName(classBytes);
        }
        if (request.getProbe() != null) {
            classBytes = wrapProbe(request, className, classBytes);
            className = classNameParser.parseClassName(classBytes);
        }
        if (request.getEntryMethod() != null && !request.getEntryMethod().trim().isEmpty()) {
            classBytes = EntryMethodBuilder.add(classBytes, request.getEntryMethod());
        }
        String classBase64 = ClassBytesEncoder.encode(classBytes, false);
        String packResult = PackerRegistry.getInstance().pack(constraints.getPackerName(),
                ClassPackerConfig.of(className, classBytes, classBase64, request.isByPassJavaModule()));
        return new BytecodeTransformResponse(className, classBytes.length, classBase64, packResult);
    }

    private byte[] applyTools(byte[] classBytes, BytecodeTransformRequest request) {
        String className = classNameParser.parseClassName(classBytes);
        String newClassName = resolveClassName(className, request.getNewClassName(),
                request.isRandomName());
        if (request.isByPassJavaModule() || request.isStaticInitialize()
                || !newClassName.equals(className)) {
            classBytes = redefine(classBytes, className, newClassName,
                    request.isByPassJavaModule(), request.isStaticInitialize());
        }
        if (request.isShrink()) {
            classBytes = ClassBytesShrink.shrink(classBytes, true);
        }
        if (request.isRenamePackage()) {
            classBytes = relocatePackage(classBytes, request.getRelocateFrom(), request.getRelocateTo());
        }
        ObfuscationConfig obfuscation = request.getObfuscation();
        if (obfuscation != null && obfuscation.isEnabled()) {
            ClassReader reader = new ClassReader(classBytes);
            classBytes = ClassObfuscation.obfuscate(classBytes, reader.getClassName().replace('/', '.'),
                    reader.readUnsignedShort(6), ObfuscationTarget.SHELL, obfuscation,
                    MethodContracts.CONSERVATIVE, Collections.<String, byte[]>emptyMap(),
                    request.getProbe() != null);
        }
        return classBytes;
    }

    private static byte[] redefine(byte[] classBytes, String className, String newClassName,
                                   boolean byPassJavaModule, boolean staticInitialize) {
        if (staticInitialize) {
            requireNoArgConstructor(classBytes, className);
        }
        if (byPassJavaModule) {
            classBytes = ClassInitializer.ensurePresent(classBytes);
        }
        ClassFileLocator locator = new MissingTypeLocator(new ClassFileLocator.Compound(
                ClassFileLocator.Simple.of(className, classBytes),
                ClassFileLocator.ForClassLoader.ofSystemLoader()));
        TypePool typePool = TypePool.Default.of(locator);
        TypeDescription type = typePool.describe(className).resolve();
        DynamicType.Builder<?> builder = new ByteBuddy().redefine(type, locator);
        if (!newClassName.equals(className)) {
            builder = builder.visit(new ClassRenameVisitorWrapper(className, newClassName));
        }
        if (byPassJavaModule) {
            builder = ByPassJavaModuleInterceptor.extendTypeInitializer(builder);
        }
        if (staticInitialize) {
            builder = StaticBlockSelfConstructorCall.extend(builder);
        }
        return builder.make(typePool).getBytes();
    }

    private static String resolveClassName(String oldName, String requestedName, boolean randomName) {
        if (randomName) {
            return CommonUtil.generateInjectorClassName();
        }
        String specified = trimToNull(requestedName);
        if (specified == null) {
            return oldName;
        }
        String normalized = normalizeName(specified, "类名");
        return normalized.indexOf('.') >= 0 ? normalized : join(packageOf(oldName), normalized);
    }

    private static byte[] relocatePackage(byte[] classBytes, String relocateFrom, String relocateTo) {
        String from = trimToNull(relocateFrom);
        String to = trimToNull(relocateTo);
        if (from == null || to == null) {
            throw new IllegalArgumentException("包名重命名需要同时填写原包名前缀与新包名前缀");
        }
        return ClassRenameUtils.relocateClass(classBytes,
                normalizeName(from, "原包名前缀"), normalizeName(to, "新包名前缀"));
    }

    private static String normalizeName(String name, String label) {
        String value = name.trim().replace('/', '.');
        if (!CLASS_NAME.matcher(value).matches()) {
            throw new IllegalArgumentException(label + "不是合法的类名/包名：" + name);
        }
        return value;
    }

    private static void requireNoArgConstructor(byte[] classBytes, String className) {
        final boolean[] found = {false};
        new ClassReader(classBytes).accept(new ClassVisitor(Opcodes.ASM9) {
            @Override
            public MethodVisitor visitMethod(int access, String name, String descriptor,
                                             String signature, String[] exceptions) {
                found[0] |= "<init>".equals(name) && NO_ARG_CONSTRUCTOR.equals(descriptor);
                return null;
            }
        }, ClassReader.SKIP_CODE | ClassReader.SKIP_DEBUG | ClassReader.SKIP_FRAMES);
        if (!found[0]) {
            throw new IllegalArgumentException("类中没有无参构造方法，无法触发静态初始化：" + className);
        }
    }

    private static String join(String packageName, String simpleName) {
        return packageName.isEmpty() ? simpleName : packageName + "." + simpleName;
    }

    private static String packageOf(String className) {
        int index = className.lastIndexOf('.');
        return index < 0 ? "" : className.substring(0, index);
    }

    private static String trimToNull(String value) {
        if (value == null) {
            return null;
        }
        String trimmed = value.trim();
        return trimmed.isEmpty() ? null : trimmed;
    }

    private static byte[] wrapProbe(BytecodeTransformRequest request, String className, byte[] classBytes) {
        ProbeConfig probeConfig = request.getProbe();
        probeConfig.setTargetJreVersion(Opcodes.V1_6);
        probeConfig.setByPassJavaModule(request.isByPassJavaModule());
        probeConfig.setShrink(request.isShrink());
        probeConfig.setStaticInitialize(request.isStaticInitialize());
        return ResponseGenerator.wrapBytecode(probeConfig, request.getServer(),
                className + "Wrapper", classBytes);
    }
}
