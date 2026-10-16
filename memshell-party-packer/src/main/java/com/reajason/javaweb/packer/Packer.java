package com.reajason.javaweb.packer;

/**
 * @author ReaJason
 * @since 2024/11/26
 */
public interface Packer {

    /**
     * 将自定义类打包成特定 payload
     *
     * @param classPackerConfig 自定义类信息
     * @return 字符串 payload
     */
    default String pack(ClassPackerConfig classPackerConfig) {
        throw new UnsupportedOperationException("当前 " + this.getClass().getSimpleName() + " 不支持 string 生成");
    }
}