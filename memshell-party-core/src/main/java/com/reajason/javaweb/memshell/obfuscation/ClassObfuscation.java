package com.reajason.javaweb.memshell.obfuscation;

import com.reajason.javaweb.GenerationException;
import com.reajason.javaweb.memshell.config.ObfuscationConfig;
import com.reajason.javaweb.utils.CommonUtil;
import me.n1ar4.clazz.obfuscator.config.BaseConfig;
import org.objectweb.asm.*;

import java.io.IOException;
import java.nio.file.DirectoryStream;
import java.nio.file.FileVisitResult;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.SimpleFileVisitor;
import java.nio.file.attribute.BasicFileAttributes;
import java.security.SecureRandom;
import java.util.*;
import java.util.logging.Logger;

/**
 * 字节码混淆门面：封装 class-obf，提供开箱即用的极简 API 与全量生成 API。
 * <p>
 * class-obf 的临时 class 与产物经 {@link ClassObfRuntime} 重定向到每次调用独立的临时目录，
 * 不依赖进程 CWD 可写（容器内非 root 用户、只读工作目录、双击启动 jar 等场景均可混淆）。
 *
 * @author ReaJason
 */
public final class ClassObfuscation {

    private static final SecureRandom RANDOM = new SecureRandom();
    private static final Logger LOG = Logger.getLogger(ClassObfuscation.class.getName());
    private static final String ID_START = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";
    private static final String ID_CHARS = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";

    /**
     * shell 字节码以 base64(gzip(shell)) 单字符串 LDC 嵌入 injector，class 文件 UTF8 常量上限 65535，
     * base64 4/3 膨胀后 gzip 产物不得超过该值。标准 Base64 下 49149 字节恰好编码为 65532 字符，
     * 而 49150 字节会编码为 65536 字符，超过上限。
     */
    public static final int MAX_EMBEDDABLE_GZIP_SIZE = 49149;

    /**
     * String 字段/局部变量的类型描述符。
     */
    private static final String STRING_DESCRIPTOR = "Ljava/lang/String;";

    private ClassObfuscation() {
    }

    /**
     * 极简便捷重载：通过 ClassReader 自动解析类名与 targetJreVersion，应用 STRONG 基线与 CONSERVATIVE 契约。
     * <p>
     * 该重载不假设产物会嵌入字符串常量，因此不做可嵌入体积校验；需要嵌入时请使用全量重载并显式传入
     * {@code enforceEmbeddableLimit=true}。
     */
    public static byte[] obfuscate(byte[] classBytes) {
        return obfuscate(classBytes, ObfuscationConfig.enabled());
    }

    /**
     * 极简便捷重载：传入自定义配置。
     */
    public static byte[] obfuscate(byte[] classBytes, ObfuscationConfig config) {
        if (classBytes == null || classBytes.length == 0) {
            return classBytes;
        }
        if (config == null || !config.isEnabled()) {
            return classBytes;
        }
        ClassReader cr;
        try {
            cr = new ClassReader(classBytes);
        } catch (Exception e) {
            throw new GenerationException("Failed to read class bytecode: " + e.getMessage(), e);
        }
        String className = cr.getClassName().replace('/', '.');
        int targetJreVersion = cr.readShort(6) & 0xFFFF;
        return obfuscate(classBytes, className, targetJreVersion, ObfuscationTarget.SHELL, config,
                MethodContracts.CONSERVATIVE, Collections.<String>emptySet(),
                Collections.<String, byte[]>emptyMap(), false);
    }

    /**
     * 全量混淆方法（面向生成链路）。
     * <p>
     * 该重载不启用可嵌入体积校验；需要把产物嵌入字符串常量时使用带
     * {@code enforceEmbeddableLimit} 的重载。
     */
    public static byte[] obfuscate(
            byte[] classBytes,
            String className,
            int targetJreVersion,
            ObfuscationTarget target,
            ObfuscationConfig config,
            Set<MethodSignature> contracts,
            Map<String, byte[]> relatedClasses) {
        return obfuscate(classBytes, className, targetJreVersion, target, config, contracts,
                Collections.<String>emptySet(), relatedClasses, false);
    }

    /**
     * @param fieldContracts 注入器按名反射读写的 shell 字段名。class-obf 没有字段黑名单能力，
     *                       非空时本次混淆整体关闭字段名混淆，保证注入器的反射查找不落空。
     *                       仅 shell 混淆需要；注入器自身的跨类字段访问由 relatedClasses 扫描保护。
     */
    public static byte[] obfuscate(
            byte[] classBytes,
            String className,
            int targetJreVersion,
            ObfuscationTarget target,
            ObfuscationConfig config,
            Set<MethodSignature> contracts,
            Set<String> fieldContracts,
            Map<String, byte[]> relatedClasses) {
        return obfuscate(classBytes, className, targetJreVersion, target, config, contracts,
                fieldContracts, relatedClasses, false);
    }

    /**
     * @param target                 产物用途标记，仅用于调用方语义区分；是否校验可嵌入体积由
     *                               {@code enforceEmbeddableLimit} 显式控制
     * @param enforceEmbeddableLimit 产物将以 base64(gzip(bytes)) 单字符串常量嵌入宿主类时传 true
     *                               （shell 恒需嵌入 injector；injector 仅在 probe 且非 Agent 类型时
     *                               需嵌入回显 Wrapper，调用方应与 Wrapper 包装条件保持一致）
     */
    public static byte[] obfuscate(
            byte[] classBytes,
            String className,
            int targetJreVersion,
            ObfuscationTarget target,
            ObfuscationConfig config,
            Set<MethodSignature> contracts,
            Map<String, byte[]> relatedClasses,
            boolean enforceEmbeddableLimit) {
        return obfuscate(classBytes, className, targetJreVersion, target, config, contracts,
                Collections.<String>emptySet(), relatedClasses, enforceEmbeddableLimit);
    }

    /**
     * @param fieldContracts 注入器按名反射读写的 shell 字段名，非空时关闭字段名混淆
     * @see #obfuscate(byte[], String, int, ObfuscationTarget, ObfuscationConfig, Set, Map, boolean)
     */
    public static byte[] obfuscate(
            byte[] classBytes,
            String className,
            int targetJreVersion,
            ObfuscationTarget target,
            ObfuscationConfig config,
            Set<MethodSignature> contracts,
            Set<String> fieldContracts,
            Map<String, byte[]> relatedClasses,
            boolean enforceEmbeddableLimit) {
        if (classBytes == null || classBytes.length == 0) {
            return classBytes;
        }
        if (config == null || !config.isEnabled()) {
            return classBytes;
        }

        // 1. 版本兼容性前置检查：<= 1.5 或包含 jsr/ret 指令直接报错
        preCheckBytecode(classBytes);

        // 2. 契约并集合并与跨类引用扫描
        Set<String> blacklist = buildBlacklist(contracts, config.getOptions());
        CrossClassScanResult scanResult = null;
        if (relatedClasses != null && !relatedClasses.isEmpty()) {
            scanResult = scanRelatedClasses(className, relatedClasses);
            blacklist.addAll(scanResult.calledMethods);
        }
        // 字段名混淆无法按字段名豁免：注入器按名反射读写的 shell 字段或跨类字段访问存在时，
        // 一律关闭字段名混淆，否则反射查找会落空
        boolean disableFieldName = (fieldContracts != null && !fieldContracts.isEmpty())
                || (scanResult != null && scanResult.fieldAccessed);

        // 未知选项键/非法值在这里就抛出：放进降级循环会被重试消耗并包装成阶梯耗尽，掩盖真实配置错误
        OptionRegistry.validateAndNormalize(config.getOptions());

        // class-obf 会向类中注入 private static 字段，接口因此变成非法字节码（字段只能是
        // public static final）。接口没有可混淆的方法体，且其方法名通常就是外部调用契约，保持原样。
        if ((new ClassReader(classBytes).getAccess() & Opcodes.ACC_INTERFACE) != 0) {
            validateOutput(classBytes, className, targetJreVersion);
            if (enforceEmbeddableLimit) {
                checkEmbeddable(classBytes);
            }
            return classBytes;
        }

        // class-obf 的中间文件全部由 ClassObfRuntime 重定向到本次调用的临时目录，
        // 不再依赖进程 CWD 可写；每次调用在独立类加载器中执行，静态状态互不影响。
        Path cwd = Paths.get(".").toAbsolutePath().normalize();
        GenerationException failure = null;
        for (int rung = RUNG_STRONG; rung <= RUNG_RENAME_ONLY; rung++) {
            BaseConfig baseConfig = buildRungConfig(config.getOptions(), blacklist,
                    disableFieldName, rung);
            try {
                return runClassObf(classBytes, baseConfig, cwd, className, targetJreVersion,
                        enforceEmbeddableLimit);
            } catch (GenerationException e) {
                failure = e;
                if (rung < RUNG_RENAME_ONLY) {
                    LOG.warning("Class obfuscation of " + className + " failed at "
                            + RUNG_NAMES[rung] + " level (" + e.getMessage()
                            + "), degrading to " + RUNG_NAMES[rung + 1]);
                }
            }
        }
        throw new GenerationException("Class obfuscation of " + className
                + " failed at every degradation level (STRONG -> LIGHT -> RENAME_ONLY), last error: "
                + (failure == null ? "unknown" : failure.getMessage()), failure);
    }

    /**
     * 降级阶梯档位：STRONG（全量 STRONG 基线）→ LIGHT（关 XOR/控制流）→ RENAME_ONLY（只剩改名类变换）。
     * <p>
     * class-obf 的 XORTransformer 在 {@code Files.delete(temp)} 之后才 {@code toByteArray()}，
     * 近 64KB 大方法（NeoreGeorg 模板的 doFilter）被 XOR 表达式撑爆 MethodTooLarge 后 temp 文件
     * 丢失、后续变换级联失败，且 {@code Result} 把真实原因吞成恒定的 "error" —— 无法按失败原因
     * 精确降级，只能统一在失败时降档。RENAME_ONLY 不引入任何方法体膨胀，方法不会比原类更大，
     * 因此必然能跑过 MethodTooLarge 类失败。
     */
    private static final int RUNG_STRONG = 0;
    private static final int RUNG_LIGHT = 1;
    private static final int RUNG_RENAME_ONLY = 2;
    private static final String[] RUNG_NAMES = {"STRONG", "LIGHT", "RENAME_ONLY"};

    private static BaseConfig buildRungConfig(Map<String, Object> options, Set<String> blacklist,
                                              boolean disableFieldName, int rung) {
        // STRONG 基线 + 随机混淆标识符
        BaseConfig baseConfig = buildStrongBaseline();

        // 用户 options 覆盖默认值（统一经 OptionRegistry 校验，遇未知键抛异常）
        OptionRegistry.apply(baseConfig, options);

        // 反射按名访问的字段（shell 字段契约）或跨类字段访问存在时自动关闭字段名混淆
        if (disableFieldName) {
            baseConfig.setEnableFieldName(false);
        }
        baseConfig.setMethodBlackList(blacklist.toArray(new String[0]));
        degradeToRung(baseConfig, rung);
        return baseConfig;
    }

    private static void degradeToRung(BaseConfig config, int rung) {
        if (rung >= RUNG_LIGHT) {
            // XOR 与控制流平坦化是方法体膨胀的主要来源：int 常量展开为异或表达式、
            // 控制流打散成倍放大指令数，大方法因此撑爆 64KB Code 属性上限
            config.setEnableXOR(false);
            config.setEnableControlFlow(false);
        }
        if (rung >= RUNG_RENAME_ONLY) {
            config.setEnableAES(false);
            config.setEnableAdvanceString(false);
            config.setEnableShuffleMember(false);
            // 改名之外的可选变换一并关闭，保证最后一档只做最小改写
            config.setEnableHideField(false);
            config.setEnableHideMethod(false);
            config.setUseEvilCharInstead(false);
            config.setAntiAI(false);
            config.setEnableInvokeDynamic(false);
            config.setEnableImageCrash(false);
            config.setEnableTrim(false);
            config.setEnableExpandMethod(false);
        }
    }

    /**
     * 单档混淆尝试：自带临时文件准备、class-obf 调用、产物校验与清理，抛出的失败由上层阶梯接管。
     */
    private static byte[] runClassObf(byte[] classBytes, BaseConfig baseConfig, Path cwd,
                                      String className, int targetJreVersion,
                                      boolean enforceEmbeddableLimit) {
        Path workDir = null;
        try {
            cleanTempFiles(cwd);

            // class-obf 的 AES 只处理方法体内的 LDC；先按开关把静态 String 字段的
            // ConstantValue 搬到 <clinit>，避免字段值以明文留在常量池里。
            byte[] preparedBytes = baseConfig.isEnableAES()
                    ? hoistStaticStringConstantFields(classBytes)
                    : classBytes;

            // 每次尝试使用独立的类加载器与临时目录：class-obf 的相对路径临时文件被
            // ClassObfRuntime 重定向到这里，失败/中断时也能在 finally 中完整清理，
            // 同时避免多个调用共用 class-obf<random>.class 命名空间。
            workDir = Files.createTempDirectory("memshell-party-obf-");
            String stem = randomIdentifier(12);
            byte[] output = ClassObfRuntime.obfuscate(preparedBytes, baseConfig, workDir, stem);
            if (baseConfig.isEnableAES()) {
                output = dropUnusedConstantPoolEntries(output);
            }

            // 执行约束校验：输出类名一致，major version <= targetJreVersion，可被 ASM 正常解析
            validateOutput(output, className, targetJreVersion);
            if (enforceEmbeddableLimit) {
                checkEmbeddable(output);
            }
            return output;
        } catch (GenerationException e) {
            throw e;
        } catch (Exception e) {
            throw new GenerationException("Class obfuscation failed: " + e.getMessage(), e);
        } finally {
            deleteRecursivelyQuietly(workDir);
            cleanTempFiles(cwd);
        }
    }

    private static void deleteRecursivelyQuietly(Path dir) {
        if (dir == null || !Files.exists(dir)) {
            return;
        }
        try {
            Files.walkFileTree(dir, new SimpleFileVisitor<Path>() {
                @Override
                public FileVisitResult visitFile(Path file, BasicFileAttributes attrs) throws IOException {
                    Files.deleteIfExists(file);
                    return FileVisitResult.CONTINUE;
                }

                @Override
                public FileVisitResult postVisitDirectory(Path directory, IOException exc) throws IOException {
                    Files.deleteIfExists(directory);
                    return FileVisitResult.CONTINUE;
                }
            });
        } catch (Exception ignored) {
        }
    }

    /**
     * 产物需以 base64(gzip(bytes)) 单字符串常量嵌入宿主类时，校验 gzip 后体积不超上限。
     */
    private static void checkEmbeddable(byte[] classBytes) {
        int gzipped = CommonUtil.gzipCompress(classBytes).length;
        if (gzipped > MAX_EMBEDDABLE_GZIP_SIZE) {
            throw new GenerationException("Obfuscated class too large to embed as string constant: gzipped "
                    + gzipped + " > " + MAX_EMBEDDABLE_GZIP_SIZE);
        }
    }

    /**
     * 系统契约与用户 options.methodBlackList 取并集。
     */
    private static Set<String> buildBlacklist(Set<MethodSignature> contracts, Map<String, Object> options) {
        Set<String> blacklist = new LinkedHashSet<>();
        if (contracts != null) {
            for (MethodSignature sig : contracts) {
                if (sig != null && sig.getName() != null) {
                    blacklist.add(sig.getName());
                }
            }
        }

        // 合并用户 options 中指定的 methodBlackList
        Object userBlacklist = options.get("methodBlackList");
        if (userBlacklist != null) {
            if (userBlacklist instanceof String[]) {
                blacklist.addAll(Arrays.asList((String[]) userBlacklist));
            } else if (userBlacklist instanceof Collection<?>) {
                for (Object item : (Collection<?>) userBlacklist) {
                    if (item != null) {
                        blacklist.add(String.valueOf(item).trim());
                    }
                }
            } else {
                for (String part : String.valueOf(userBlacklist).split("[,;]")) {
                    String trimmed = part.trim();
                    if (!trimmed.isEmpty()) {
                        blacklist.add(trimmed);
                    }
                }
            }
        }
        return blacklist;
    }

    private static BaseConfig buildStrongBaseline() {
        BaseConfig config = new BaseConfig();
        config.setEnableDeleteCompileInfo(true);
        config.setEnableAES(true);
        config.setEnableAdvanceString(true);
        config.setEnableXOR(true);
        config.setEnableFieldName(true);
        config.setEnableMethodName(true);
        config.setEnableParamName(true);
        // 花指令会在每个方法调用前插入 new String("...") 等无用片段，产物里只留噪音。
        config.setEnableJunk(false);
        // class-obf 的 BaseConfig.isValid() 无条件校验 junk 参数范围，即使开关关闭也须填合法值。
        config.setJunkLevel(1);
        config.setMaxJunkOneClass(1);
        config.setEnableShuffleMember(true);
        config.setEnableControlFlow(true);
        config.setAutoDisableImpl(true);
        config.setIgnorePublic(false);
        config.setAsmAutoCompute(true);
        config.setQuiet(true);
        config.setLogLevel("info");
        config.setObfuscateChars(new String[]{"i", "l", "L", "1", "I"});
        config.setBadAnnoLevel(3);
        config.setEnableBadAnno(false);

        // 随机生成混淆标识符
        config.setAesKey(randomAlphanumeric(16));
        config.setAesDecName(randomIdentifier(10));
        config.setAesKeyField(randomIdentifier(10));
        config.setAdvanceStringName(randomIdentifier(8));
        return config;
    }

    /**
     * 用全新的 ClassWriter 重写一遍，重建常量池并丢弃未被引用的常量。
     * <p>
     * ASM 的 {@code ClassWriter(ClassReader, flags)} 会整份复制输入常量池以加速写出，
     * 即使 LDC 已被 AES 替换成密文，原明文字符串仍会作为“无人引用的常量”留在 class 文件里，
     * 用 strings/常量池扫描依旧能还原 payload。重建后只保留真正被引用的常量。
     */
    private static byte[] dropUnusedConstantPoolEntries(byte[] classBytes) {
        ClassReader cr = new ClassReader(classBytes);
        ClassWriter cw = new ClassWriter(0);
        cr.accept(cw, 0);
        return cw.toByteArray();
    }

    /**
     * 把 static String 字段的 ConstantValue 搬到 {@code <clinit>} 的 LDC 赋值。
     * <p>
     * class-obf 的 enableAES 只改写方法体里的 LDC 常量，字段 ConstantValue 会以明文
     * 留在 class 文件中（ByteBuddy 生成的 paramName/pass/headerValue 等字段即属此类）。
     * 搬迁后字段初始化变成 {@code <clinit>} 中的 LDC，随其他方法体字符串一起被 AES 加密。
     * 语义等价：ConstantValue 本来就在类初始化时生效，而赋值被放在 {@code <clinit>} 最前面。
     * 无此类字段时返回原字节码，保证未开启 AES 或无需搬迁时产物不变。
     */
    static byte[] hoistStaticStringConstantFields(byte[] classBytes) {
        final Map<String, String> constants = new LinkedHashMap<>();
        final String[] owner = new String[1];
        final boolean[] hasClinit = new boolean[1];
        ClassReader reader = new ClassReader(classBytes);
        ClassWriter writer = new ClassWriter(reader, ClassWriter.COMPUTE_MAXS);
        reader.accept(new ClassVisitor(Opcodes.ASM9, writer) {
            @Override
            public void visit(int version, int access, String name, String signature,
                              String superName, String[] interfaces) {
                owner[0] = name;
                super.visit(version, access, name, signature, superName, interfaces);
            }

            @Override
            public FieldVisitor visitField(int access, String name, String descriptor,
                                           String signature, Object value) {
                if ((access & Opcodes.ACC_STATIC) != 0
                        && STRING_DESCRIPTOR.equals(descriptor)
                        && value instanceof String) {
                    constants.put(name, (String) value);
                    return super.visitField(access, name, descriptor, signature, null);
                }
                return super.visitField(access, name, descriptor, signature, value);
            }

            @Override
            public MethodVisitor visitMethod(int access, String name, String descriptor,
                                             String signature, String[] exceptions) {
                MethodVisitor mv = super.visitMethod(access, name, descriptor, signature, exceptions);
                if (!"<clinit>".equals(name)) {
                    return mv;
                }
                hasClinit[0] = true;
                return new MethodVisitor(Opcodes.ASM9, mv) {
                    @Override
                    public void visitCode() {
                        super.visitCode();
                        emitStaticStringAssignments(mv, owner[0], constants);
                    }
                };
            }

            @Override
            public void visitEnd() {
                if (!constants.isEmpty() && !hasClinit[0]) {
                    MethodVisitor mv = super.visitMethod(Opcodes.ACC_STATIC, "<clinit>", "()V", null, null);
                    mv.visitCode();
                    emitStaticStringAssignments(mv, owner[0], constants);
                    mv.visitInsn(Opcodes.RETURN);
                    mv.visitMaxs(0, 0);
                    mv.visitEnd();
                }
                super.visitEnd();
            }
        }, 0);
        return constants.isEmpty() ? classBytes : writer.toByteArray();
    }

    private static void emitStaticStringAssignments(MethodVisitor mv, String owner, Map<String, String> constants) {
        for (Map.Entry<String, String> entry : constants.entrySet()) {
            mv.visitLdcInsn(entry.getValue());
            mv.visitFieldInsn(Opcodes.PUTSTATIC, owner, entry.getKey(), STRING_DESCRIPTOR);
        }
    }

    private static void preCheckBytecode(byte[] classBytes) {
        ClassReader cr;
        try {
            cr = new ClassReader(classBytes);
        } catch (Exception e) {
            throw new GenerationException("Failed to parse bytecode for pre-check: " + e.getMessage(), e);
        }
        int majorVersion = cr.readShort(6) & 0xFFFF;
        if (majorVersion <= 49) { // Java 1.5 or older
            throw new GenerationException("Cannot obfuscate class with version <= 1.5 (major version " + majorVersion + ")");
        }
        final boolean[] hasJsrOrRet = new boolean[1];
        cr.accept(new ClassVisitor(Opcodes.ASM9) {
            @Override
            public MethodVisitor visitMethod(int access, String name, String descriptor, String signature, String[] exceptions) {
                return new MethodVisitor(Opcodes.ASM9) {
                    @Override
                    public void visitJumpInsn(int opcode, Label label) {
                        if (opcode == Opcodes.JSR) {
                            hasJsrOrRet[0] = true;
                        }
                        super.visitJumpInsn(opcode, label);
                    }

                    @Override
                    public void visitVarInsn(int opcode, int varIndex) {
                        if (opcode == Opcodes.RET) {
                            hasJsrOrRet[0] = true;
                        }
                        super.visitVarInsn(opcode, varIndex);
                    }
                };
            }
        }, ClassReader.SKIP_DEBUG | ClassReader.SKIP_FRAMES);

        if (hasJsrOrRet[0]) {
            throw new GenerationException("Cannot obfuscate class containing JSR/RET instructions");
        }
    }

    private static void validateOutput(byte[] outputBytes, String expectedClassName, int targetJreVersion) {
        ClassReader cr;
        try {
            cr = new ClassReader(outputBytes);
        } catch (Exception e) {
            throw new GenerationException("Obfuscated bytecode cannot be parsed by ASM: " + e.getMessage(), e);
        }
        String actualClassName = cr.getClassName().replace('/', '.');
        if (!expectedClassName.equals(actualClassName)) {
            throw new GenerationException("Obfuscated class name mismatch: expected '" + expectedClassName + "', but got '" + actualClassName + "'");
        }
        int outVersion = cr.readShort(6) & 0xFFFF;
        int maxAllowedVersion = targetJreVersion & 0xFFFF;
        if (outVersion > maxAllowedVersion) {
            throw new GenerationException("Obfuscated class version (" + outVersion + ") exceeds target JRE version (" + maxAllowedVersion + ")");
        }
    }

    private static final class CrossClassScanResult {
        final Set<String> calledMethods;
        final boolean fieldAccessed;

        CrossClassScanResult(Set<String> calledMethods, boolean fieldAccessed) {
            this.calledMethods = calledMethods;
            this.fieldAccessed = fieldAccessed;
        }
    }

    private static CrossClassScanResult scanRelatedClasses(String outerClassName, Map<String, byte[]> relatedClasses) {
        final String outerInternal = outerClassName.replace('.', '/');
        final Set<String> calledMethods = new LinkedHashSet<>();
        final boolean[] fieldAccessed = new boolean[1];

        for (byte[] bytes : relatedClasses.values()) {
            if (bytes == null || bytes.length == 0) {
                continue;
            }
            try {
                ClassReader cr = new ClassReader(bytes);
                cr.accept(new ClassVisitor(Opcodes.ASM9) {
                    @Override
                    public MethodVisitor visitMethod(int access, String name, String descriptor, String signature, String[] exceptions) {
                        return new MethodVisitor(Opcodes.ASM9) {
                            @Override
                            public void visitMethodInsn(int opcode, String owner, String methodName, String desc, boolean isInterface) {
                                if (outerInternal.equals(owner)) {
                                    calledMethods.add(methodName);
                                }
                                super.visitMethodInsn(opcode, owner, methodName, desc, isInterface);
                            }

                            @Override
                            public void visitFieldInsn(int opcode, String owner, String fieldName, String desc) {
                                if (outerInternal.equals(owner)) {
                                    fieldAccessed[0] = true;
                                }
                                super.visitFieldInsn(opcode, owner, fieldName, desc);
                            }
                        };
                    }
                }, ClassReader.SKIP_DEBUG | ClassReader.SKIP_FRAMES);
            } catch (Exception ignored) {
            }
        }
        return new CrossClassScanResult(calledMethods, fieldAccessed[0]);
    }

    /**
     * 清理 class-obf 可能留在 CWD 的痕迹。
     * <p>
     * 临时 class 与产物已由 ClassObfRuntime 重定向到调用方临时目录；但 class-obf 的 Runner
     * 仍会无条件尝试在 CWD 创建 {@code class-obf-lib}（失败即忽略），CWD 可写时留下空目录，
     * 这里负责收尾。另外顺带清掉旧版本/其他调用可能残留的相对路径产物。
     */
    private static void cleanTempFiles(Path cwd) {
        try {
            Path tempClass = cwd.resolve("class-obf-temp.class");
            if (Files.exists(tempClass)) {
                try {
                    Files.delete(tempClass);
                } catch (Exception ignored) {
                }
            }
            try (DirectoryStream<Path> stream = Files.newDirectoryStream(cwd, "class-obf*.class")) {
                for (Path p : stream) {
                    try {
                        Files.delete(p);
                    } catch (Exception ignored) {
                    }
                }
            } catch (Exception ignored) {
            }
            // 与 class-obf CustomClassLoader.LIB_DIR 同名（该常量在依赖类中，编译期已被内联）
            Path libDir = cwd.resolve("class-obf-lib");
            if (Files.exists(libDir) && Files.isDirectory(libDir)) {
                Path readme = libDir.resolve("README.md");
                if (Files.exists(readme)) {
                    try {
                        Files.delete(readme);
                    } catch (Exception ignored) {
                    }
                }
                try (DirectoryStream<Path> stream = Files.newDirectoryStream(libDir)) {
                    if (!stream.iterator().hasNext()) {
                        Files.delete(libDir);
                    }
                } catch (Exception ignored) {
                }
            }
        } catch (Exception ignored) {
        }
    }

    private static String randomIdentifier(int length) {
        StringBuilder sb = new StringBuilder(length);
        sb.append(ID_START.charAt(RANDOM.nextInt(ID_START.length())));
        for (int i = 1; i < length; i++) {
            sb.append(ID_CHARS.charAt(RANDOM.nextInt(ID_CHARS.length())));
        }
        return sb.toString();
    }

    private static String randomAlphanumeric(int length) {
        StringBuilder sb = new StringBuilder(length);
        for (int i = 0; i < length; i++) {
            sb.append(ID_CHARS.charAt(RANDOM.nextInt(ID_CHARS.length())));
        }
        return sb.toString();
    }
}
