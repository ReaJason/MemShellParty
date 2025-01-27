package com.reajason.javaweb.memshell.packer.jar;

import com.reajason.javaweb.memshell.config.GenerateResult;
import com.reajason.javaweb.memshell.packer.Packer;

/**
 * @author ReaJason
 * @since 2025/1/1
 */
public interface JarPacker extends Packer {
    /**
     * 将生成的内存马打包成 bytes
     *
     * @param generateResult 生成的内存马信息
     * @return 字节数组
     */
    byte[] packBytes(GenerateResult generateResult);
}
