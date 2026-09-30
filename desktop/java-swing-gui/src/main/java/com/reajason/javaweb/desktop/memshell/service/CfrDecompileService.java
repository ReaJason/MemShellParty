package com.reajason.javaweb.desktop.memshell.service;

import org.benf.cfr.reader.api.CfrDriver;
import org.benf.cfr.reader.api.ClassFileSource;
import org.benf.cfr.reader.api.OutputSinkFactory;
import org.benf.cfr.reader.bytecode.analysis.parse.utils.Pair;

import java.util.Collection;
import java.util.Collections;
import java.util.List;

/**
 * CFR 反编译服务：从生成的类字节码还原 Java 源码，供结果面板「反编译」视图使用。
 * 通过自定义 {@link ClassFileSource} 直接喂字节数组，不落临时文件；
 * 未命中的依赖类（如父类、引用类型）由 withClassFileSource 自带的默认源回退查找。
 */
public class CfrDecompileService {

    /**
     * 反编译单个类。
     *
     * @param className  全限定类名（如 com.example.Shell）
     * @param classBytes .class 字节码
     * @return Java 源码文本；CFR 部分失败时返回已还原内容（可能含错误注释）
     */
    public String decompile(String className, byte[] classBytes) {
        if (className == null || className.trim().isEmpty()) {
            throw new IllegalArgumentException("类名为空，无法反编译");
        }
        if (classBytes == null || classBytes.length == 0) {
            throw new IllegalArgumentException("类字节码为空，无法反编译");
        }
        final String targetClassName = className.trim();
        final String classFilePath = targetClassName.replace('.', '/') + ".class";
        final byte[] bytes = classBytes;

        ClassFileSource classFileSource = new ClassFileSource() {
            @Override
            public void informAnalysisRelativePathDetail(String usePath, String path) {
            }

            @Override
            public Collection<String> addJar(String jarPath) {
                return Collections.emptyList();
            }

            @Override
            public String getPossiblyRenamedPath(String path) {
                return path;
            }

            @Override
            public Pair<byte[], String> getClassFileContent(String path) {
                if (classFilePath.equals(path)) {
                    return Pair.make(bytes, targetClassName);
                }
                // 未命中返回 null，交给默认源回退（classpath 查找）
                return null;
            }
        };

        final StringBuilder source = new StringBuilder();
        OutputSinkFactory sinkFactory = new OutputSinkFactory() {
            private final Sink<Object> ignoreSink = new Sink<Object>() {
                @Override
                public void write(Object sinkable) {
                }
            };
            private final Sink<Object> javaSink = new Sink<Object>() {
                @Override
                public void write(Object sinkable) {
                    source.append(sinkable);
                }
            };

            @Override
            public List<SinkClass> getSupportedSinks(SinkType sinkType, Collection<SinkClass> collection) {
                return Collections.singletonList(SinkClass.STRING);
            }

            @Override
            @SuppressWarnings("unchecked")
            public <T> Sink<T> getSink(SinkType sinkType, SinkClass sinkClass) {
                if (sinkType == SinkType.JAVA && sinkClass == SinkClass.STRING) {
                    return (Sink<T>) javaSink;
                }
                return (Sink<T>) ignoreSink;
            }
        };

        CfrDriver driver = new CfrDriver.Builder()
                .withClassFileSource(classFileSource)
                .withOutputSink(sinkFactory)
                .build();
        driver.analyse(Collections.singletonList(classFilePath));
        return source.toString();
    }
}
