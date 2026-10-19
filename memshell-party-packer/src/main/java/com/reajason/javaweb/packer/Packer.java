package com.reajason.javaweb.packer;

/**
 * @author ReaJason
 * @since 2024/11/26
 */
public interface Packer {

    /**
     * 产物是否经 HTTP Header 传输（如 Shiro 的 rememberMe Cookie）。声明为 true 时，生成结果会
     * 回填打包后体积并按 4KB 阈值给出 Header 超限预警；子 packer 默认继承 false。
     */
    default boolean headerTransported() {
        return false;
    }

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