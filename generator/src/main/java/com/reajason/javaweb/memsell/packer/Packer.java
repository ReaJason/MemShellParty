package com.reajason.javaweb.memsell.packer;

import com.reajason.javaweb.config.GenerateResult;
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
     * @return 指定格式字节数组
     */
    byte[] pack(GenerateResult generateResult);

    /**
     * 部分打包器可能需要配置来进行额外的配置项
     *
     * @param generateResult 生成的内存马信息
     * @param config         配置
     * @return 字节数组
     */
    default byte[] pack(GenerateResult generateResult, Map<String, String> config) {
        throw new UnsupportedOperationException();
    }


    @Getter
    static enum INSTANCE {
        /**
         * JSP 打包器
         */
        JSP(new JspPacker()),

        /**
         * 脚本引擎打包器
         */
        ScriptEngine(new ScriptEnginePacker()),

        /**
         * 反序列化打包器
         */
        Deserialize(new DeserializePacker()),
        ;

        private final Packer packer;

        INSTANCE(Packer packer) {
            this.packer = packer;
        }
    }
}
