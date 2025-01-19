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
     * @return 指定格式字节数组
     */
    default String pack(GenerateResult generateResult) {
        throw new UnsupportedOperationException("当前 " + this.getClass().getSimpleName() + " 不支持 string 生成");
    }

    default byte[] packBytes(GenerateResult generateResult) {
        throw new UnsupportedOperationException("当前 " + this.getClass().getSimpleName() + " 不支持 bytes 生成");
    }

    /**
     * 部分打包器可能需要配置来进行额外的配置项
     *
     * @param generateResult 生成的内存马信息
     * @param config         配置
     * @return 字节数组
     */
    default byte[] pack(GenerateResult generateResult, Map<String, ?> config) {
        throw new UnsupportedOperationException();
    }


    @Getter
    static enum INSTANCE {
        /**
         * Base64
         */
        Base64(new Base64Packer()),

        /**
         * BCEL
         */
        BCEL(new BCELPacker()),

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

        /**
         * EL
         */
        EL(new ELPacker()),

        OGNL(new OGNLPacker()),

        SpEL(new SpELPacker()),

        Freemarker(new FreemarkerPacker()),

        Velocity(new VelocityPacker()),

        AgentJar(new AgentJarPacker()),
        ;
        private final Packer packer;

        INSTANCE(Packer packer) {
            this.packer = packer;
        }
    }
}
