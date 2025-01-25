package com.reajason.javaweb.memshell.packer;

import lombok.Getter;

/**
 * @author ReaJason
 * @since 2025/1/23
 */
@Getter
public enum Packers {
    /**
     * Base64
     */
    Base64(new Base64Packer()),

    /**
     * GzipBase64
     */
    GzipBase64(new GzipBase64()),

    Jar(new SimpleJarPacker()),

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

    SpEL(new SpELSpringIOUtilsGzipPacker()),

    Freemarker(new FreemarkerPacker()),

    Velocity(new VelocityPacker()),

    AgentJar(new AgentJarPacker()),

    XxlJob(new XxlJobPacker()),
    ;
    private final Packer instance;

    Packers(Packer instance) {
        this.instance = instance;
    }

    Packer getPacker(Packers packerType) {
        return null;
    }
}
