package com.reajason.javaweb.memsell.packer;

import com.reajason.javaweb.config.GenerateResult;
import lombok.Getter;

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


    @Getter
    static enum INSTANCE {
        /**
         * JSP 打包器
         */
        JSP(new JspPacker()),

        /**
         * 脚本引擎打包器
         */
        ScriptEngine(new ScriptEnginePacker());

        private final Packer packer;

        INSTANCE(Packer packer) {
            this.packer = packer;
        }
    }
}
