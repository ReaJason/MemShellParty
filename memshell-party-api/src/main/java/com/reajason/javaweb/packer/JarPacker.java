package com.reajason.javaweb.packer;

/**
 * 产出 jar 字节的打包器；{@code PackerRegistry.pack} 会把结果统一 Base64 编码。
 *
 * @author ReaJason
 * @since 2025/1/1
 */
public interface JarPacker extends Packer {
    /**
     * 将生成的类打包成 jar
     *
     * @param config 生成的类信息
     * @return 字节数组
     */
    byte[] packBytes(JarPackerConfig config);

    default String getPackageName(String mainClassName) {
        if (mainClassName == null || mainClassName.lastIndexOf('.') <= 0) {
            throw new IllegalArgumentException("该 Jar 打包器要求主类位于命名包中，当前类名: " + mainClassName);
        }
        return mainClassName.substring(0, mainClassName.lastIndexOf('.'));
    }
}
