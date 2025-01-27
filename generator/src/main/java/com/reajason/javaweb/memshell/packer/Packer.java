package com.reajason.javaweb.memshell.packer;

import com.reajason.javaweb.memshell.config.GenerateResult;
import lombok.Getter;

import java.util.Map;

/**
 * @author ReaJason
 * @since 2024/11/26
 */
public interface Packer {

    /**
     * 将生成的内存马打包成指定格式
     *
     * @param generateResult 生成的内存马信息
     * @return 字符串 payload
     */
    default String pack(GenerateResult generateResult) {
        throw new UnsupportedOperationException("当前 " + this.getClass().getSimpleName() + " 不支持 string 生成");
    }
}