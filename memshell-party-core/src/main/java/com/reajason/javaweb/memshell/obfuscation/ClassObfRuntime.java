package com.reajason.javaweb.memshell.obfuscation;

import com.reajason.javaweb.GenerationException;
import me.n1ar4.clazz.obfuscator.config.BaseConfig;
import org.objectweb.asm.ClassReader;
import org.objectweb.asm.ClassWriter;
import org.objectweb.asm.Opcodes;
import org.objectweb.asm.tree.AbstractInsnNode;
import org.objectweb.asm.tree.ClassNode;
import org.objectweb.asm.tree.InsnNode;
import org.objectweb.asm.tree.LdcInsnNode;
import org.objectweb.asm.tree.MethodInsnNode;
import org.objectweb.asm.tree.MethodNode;
import org.objectweb.asm.tree.VarInsnNode;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.lang.reflect.Constructor;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.nio.file.Files;
import java.nio.file.Path;

/**
 * 以隔离类加载器执行 class-obf，把它的相对路径临时文件重定向到本次调用的 workDir。
 * <p>
 * 直接调用 {@code ClassObf.run(Path)} 会用到两个 CWD 相对路径：
 * <ul>
 *     <li>{@code Const.TEMP_PATH}（{@code class-obf-temp.class}）——输入与所有变换的中间产物；</li>
 *     <li>{@code FileUtil.getFileNameWithoutExt} 拼出的 {@code <name>_obf.class}——最终产物。</li>
 * </ul>
 * 隔离加载器在定义这两个类时改写字节码：{@code Const} 的 {@code "class-obf-temp.class"}
 * 常量替换为 workDir 下的绝对路径，{@code FileUtil} 的方法体替换为返回 workDir 下的绝对产物名。
 * class-obf 的其余类仍从依赖 jar 原样加载，因此不引入分叉实现。
 * <p>
 * 每次混淆调用使用全新的加载器：class-obf 的静态状态（{@code AnalyzeEnv}/{@code ObfEnv}/
 * {@code NameUtil.CHAR_POOL} 等）随加载器隔离，失败重试的降级阶梯之间、并发调用之间都不会
 * 互相污染，也不再需要进程内/跨进程锁。{@code config.BaseConfig} 由父加载器共享，以保证
 * 与 {@link OptionRegistry} 构造的配置对象类型一致。
 *
 * @author ReaJason
 */
final class ClassObfRuntime {

    private static final String CLASS_OBF = "me.n1ar4.clazz.obfuscator.api.ClassObf";
    private static final String BASE_CONFIG = "me.n1ar4.clazz.obfuscator.config.BaseConfig";
    private static final String CONST = "me.n1ar4.clazz.obfuscator.Const";
    private static final String FILE_UTIL = "me.n1ar4.clazz.obfuscator.utils.FileUtil";
    private static final String FILE_UTIL_METHOD = "getFileNameWithoutExt";
    private static final String FILE_UTIL_DESCRIPTOR = "(Ljava/nio/file/Path;)Ljava/lang/String;";
    private static final String TEMP_CLASS_NAME = "class-obf-temp.class";
    private static final String OBF_PACKAGE_PREFIX = "me.n1ar4.";
    private static final String SCRATCH_INTERNAL_NAME =
            ObfuscationScratch.class.getName().replace('.', '/');

    private ClassObfRuntime() {
    }

    /**
     * 执行单次混淆。输入落到 workDir，class-obf 的中间文件与产物也都在 workDir，
     * 返回前所有文件由调用方随 workDir 一起清理。
     */
    static byte[] obfuscate(byte[] classBytes, BaseConfig config, Path workDir, String stem) {
        Path inputPath = workDir.resolve(stem + ".class");
        try {
            Files.write(inputPath, classBytes);
        } catch (IOException e) {
            throw new GenerationException("Failed to write obfuscation input: " + e.getMessage(), e);
        }

        ObfuscationScratch.enter(workDir);
        try {
            ClassLoader loader = new PatchedClassObfClassLoader(ClassObfRuntime.class.getClassLoader());
            Class<?> classObfType = Class.forName(CLASS_OBF, true, loader);
            Class<?> configType = Class.forName(BASE_CONFIG, false, loader);

            Constructor<?> constructor = classObfType.getConstructor(configType);
            Object classObf = constructor.newInstance(config);
            Method run = classObfType.getMethod("run", Path.class);
            Object result = run.invoke(classObf, inputPath);

            Class<?> resultType = result.getClass();
            String success = (String) resultType.getField("SUCCESS").get(null);
            String message = (String) resultType.getMethod("getMessage").invoke(result);
            byte[] data = (byte[]) resultType.getMethod("getData").invoke(result);
            if (!success.equals(message) || data == null) {
                throw new GenerationException("Class obfuscation failed: " + message);
            }
            return data;
        } catch (InvocationTargetException e) {
            Throwable cause = e.getCause() == null ? e : e.getCause();
            throw new GenerationException("Class obfuscation failed: " + cause.getMessage(), cause);
        } catch (GenerationException e) {
            throw e;
        } catch (LinkageError e) {
            // 隔离加载器定义 class-obf 类时的链接失败（缺类、类初始化失败等）
            throw new GenerationException("Class obfuscation failed: " + e.getMessage(), e);
        } catch (Exception e) {
            throw new GenerationException("Class obfuscation failed: " + e.getMessage(), e);
        } finally {
            ObfuscationScratch.exit();
        }
    }

    /**
     * 子优先加载 class-obf：同一份依赖字节在新加载器中定义，静态状态与父加载器隔离。
     * BaseConfig 例外，保持父加载器定义，调用方传入的配置对象才能被 ClassObf 构造器接受。
     */
    private static final class PatchedClassObfClassLoader extends ClassLoader {

        private PatchedClassObfClassLoader(ClassLoader parent) {
            super(parent);
        }

        @Override
        protected Class<?> loadClass(String name, boolean resolve) throws ClassNotFoundException {
            if (!name.startsWith(OBF_PACKAGE_PREFIX) || BASE_CONFIG.equals(name)) {
                return super.loadClass(name, resolve);
            }
            synchronized (getClassLoadingLock(name)) {
                Class<?> loaded = findLoadedClass(name);
                if (loaded == null) {
                    byte[] bytes = readClassResource(name);
                    if (bytes == null) {
                        if (CONST.equals(name) || FILE_UTIL.equals(name)) {
                            throw new GenerationException("class-obf class not found on classpath: " + name);
                        }
                        return super.loadClass(name, resolve);
                    }
                    if (CONST.equals(name)) {
                        bytes = patchConst(bytes);
                    } else if (FILE_UTIL.equals(name)) {
                        bytes = patchFileUtil(bytes);
                    }
                    loaded = defineClass(name, bytes, 0, bytes.length);
                }
                if (resolve) {
                    resolveClass(loaded);
                }
                return loaded;
            }
        }

        private byte[] readClassResource(String name) {
            ClassLoader parent = getParent();
            if (parent == null) {
                return null;
            }
            String resource = name.replace('.', '/') + ".class";
            try (InputStream in = parent.getResourceAsStream(resource)) {
                if (in == null) {
                    return null;
                }
                ByteArrayOutputStream out = new ByteArrayOutputStream();
                byte[] buffer = new byte[4096];
                int read;
                while ((read = in.read(buffer)) != -1) {
                    out.write(buffer, 0, read);
                }
                return out.toByteArray();
            } catch (IOException e) {
                throw new GenerationException("Failed to read " + resource + ": " + e.getMessage(), e);
            }
        }

        /**
         * Const.TEMP_PATH 的静态初始化只有一处 {@code Paths.get("class-obf-temp.class")}，
         * 把该 LDC 常量换成绝对路径即可；常量数量不符说明 class-obf 版本已变化，直接报错。
         */
        private static byte[] patchConst(byte[] classBytes) {
            ClassNode node = new ClassNode();
            new ClassReader(classBytes).accept(node, 0);
            String tempPath = ObfuscationScratch.tempFileName();
            int replaced = 0;
            for (MethodNode method : node.methods) {
                for (AbstractInsnNode insn : method.instructions.toArray()) {
                    if (insn instanceof LdcInsnNode && TEMP_CLASS_NAME.equals(((LdcInsnNode) insn).cst)) {
                        ((LdcInsnNode) insn).cst = tempPath;
                        replaced++;
                    }
                }
            }
            if (replaced != 1) {
                throw new GenerationException("Unsupported class-obf version: expected exactly one "
                        + TEMP_CLASS_NAME + " constant, found " + replaced);
            }
            ClassWriter writer = new ClassWriter(0);
            node.accept(writer);
            return writer.toByteArray();
        }

        /**
         * FileUtil.getFileNameWithoutExt 决定产物文件名。整个方法体替换为返回 workDir 下的绝对
         * 产物名，输出文件因此不再写入 CWD。
         */
        private static byte[] patchFileUtil(byte[] classBytes) {
            ClassNode node = new ClassNode();
            new ClassReader(classBytes).accept(node, 0);
            boolean patched = false;
            for (MethodNode method : node.methods) {
                if (!FILE_UTIL_METHOD.equals(method.name) || !FILE_UTIL_DESCRIPTOR.equals(method.desc)) {
                    continue;
                }
                method.instructions.clear();
                method.tryCatchBlocks.clear();
                method.localVariables = null;
                method.instructions.add(new VarInsnNode(Opcodes.ALOAD, 0));
                method.instructions.add(new MethodInsnNode(Opcodes.INVOKESTATIC,
                        SCRATCH_INTERNAL_NAME, "outputStem", FILE_UTIL_DESCRIPTOR, false));
                method.instructions.add(new InsnNode(Opcodes.ARETURN));
                method.maxStack = 1;
                method.maxLocals = 1;
                patched = true;
            }
            if (!patched) {
                throw new GenerationException("Unsupported class-obf version: "
                        + FILE_UTIL + "." + FILE_UTIL_METHOD + " not found");
            }
            ClassWriter writer = new ClassWriter(0);
            node.accept(writer);
            return writer.toByteArray();
        }
    }
}
