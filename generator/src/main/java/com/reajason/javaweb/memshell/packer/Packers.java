package com.reajason.javaweb.memshell.packer;

import com.reajason.javaweb.memshell.packer.base64.Base64Packer;
import com.reajason.javaweb.memshell.packer.base64.DefaultBase64Packer;
import com.reajason.javaweb.memshell.packer.base64.GzipBase64Packer;
import com.reajason.javaweb.memshell.packer.deserialize.DeserializePacker;
import com.reajason.javaweb.memshell.packer.el.ELPacker;
import com.reajason.javaweb.memshell.packer.freemarker.FreemarkerPacker;
import com.reajason.javaweb.memshell.packer.jar.AgentJarPacker;
import com.reajason.javaweb.memshell.packer.jar.DefaultJarPacker;
import com.reajason.javaweb.memshell.packer.jsp.DefalutJspPacker;
import com.reajason.javaweb.memshell.packer.jsp.JspPacker;
import com.reajason.javaweb.memshell.packer.jsp.JspxPacker;
import com.reajason.javaweb.memshell.packer.mvel.MVELPacker;
import com.reajason.javaweb.memshell.packer.ognl.OGNLPacker;
import com.reajason.javaweb.memshell.packer.scriptengine.ScriptEnginePacker;
import com.reajason.javaweb.memshell.packer.spel.SpELPacker;
import com.reajason.javaweb.memshell.packer.spel.SpELScriptEnginePacker;
import com.reajason.javaweb.memshell.packer.spel.SpELSpringIOUtilsGzipPacker;
import com.reajason.javaweb.memshell.packer.spel.SpELSpringUtilsPacker;
import com.reajason.javaweb.memshell.packer.velocity.VelocityPacker;
import lombok.Getter;

import java.util.List;
import java.util.Objects;
import java.util.stream.Stream;

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
    DefaultBase64(new DefaultBase64Packer(), Base64Packer.class),
    GzipBase64(new GzipBase64Packer(), Base64Packer.class),

    Jar(new DefaultJarPacker()),

    /**
     * BCEL
     */
    BCEL(new BCELPacker()),

    /**
     * JSP 打包器
     */
    JSP(new JspPacker()),
    DefaultJSP(new DefalutJspPacker(), JspPacker.class),
    JSPX(new JspxPacker(), JspPacker.class),

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
    MVEL(new MVELPacker()),

    SpEL(new SpELPacker()),
    SpELScriptEngine(new SpELScriptEnginePacker(), SpELPacker.class),
    SpELSpringIOUtils(new SpELSpringIOUtilsGzipPacker(), SpELPacker.class),
    SpELSpringUtils(new SpELSpringUtilsPacker(), SpELPacker.class),

    Freemarker(new FreemarkerPacker()),

    Velocity(new VelocityPacker()),

    AgentJar(new AgentJarPacker()),

    XxlJob(new XxlJobPacker()),
    ;
    private final Packer instance;
    private Class<?> parentPacker = null;

    Packers(Packer instance) {
        this.instance = instance;
    }

    Packers(Packer instance, Class<?> parentPacker) {
        this.instance = instance;
        this.parentPacker = parentPacker;
    }

    public static Packer getPacker(Packers packerType) {
        return null;
    }

    public static List<Packers> getPackersWithParent(Class<?> parentPacker) {
        return Stream.of(Packers.values()).filter(p -> Objects.equals(p.getParentPacker(), parentPacker)).toList();
    }
}
