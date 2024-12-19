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
    String pack(GenerateResult generateResult);

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
        Base64("Base64", new Base64Packer()),

        /**
         * BCEL
         */
        BCEL("BCEL", new BCELPacker()),

        /**
         * JSP 打包器
         */
        JSP("JSP", new JspPacker()),

        /**
         * 脚本引擎打包器
         */
        ScriptEngine("脚本引擎", new ScriptEnginePacker()),

        /**
         * 反序列化打包器
         */
        Deserialize("反序列化(Only CB4, 1.9.x)", new DeserializePacker()),

        /**
         * EL
         */
        EL("EL 表达式", new ELPacker()),

        OGNL("OGNL 表达式", new OGNLPacker()),

        SpEL("SpEL 表达式", new SpELPacker()),

        Freemarker("Freemarker", new FreemarkerPacker()),

        Velocity("Velocity", new VelocityPacker()),
        ;

        private final String desc;
        private final Packer packer;

        INSTANCE(String desc, Packer packer) {
            this.desc = desc;
            this.packer = packer;
        }
    }
}
