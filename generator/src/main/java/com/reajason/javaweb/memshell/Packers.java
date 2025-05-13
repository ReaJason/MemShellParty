package com.reajason.javaweb.memshell;

import com.reajason.javaweb.memshell.packer.BCELPacker;
import com.reajason.javaweb.memshell.packer.Packer;
import com.reajason.javaweb.memshell.packer.XxlJobPacker;
import com.reajason.javaweb.memshell.packer.aviator.AviatorPacker;
import com.reajason.javaweb.memshell.packer.base64.Base64Packer;
import com.reajason.javaweb.memshell.packer.base64.DefaultBase64Packer;
import com.reajason.javaweb.memshell.packer.base64.GzipBase64Packer;
import com.reajason.javaweb.memshell.packer.bsh.BeanShellPacker;
import com.reajason.javaweb.memshell.packer.deserialize.hessian.Hessian2Packer;
import com.reajason.javaweb.memshell.packer.deserialize.hessian.Hessian2XSLTScriptEnginePacker;
import com.reajason.javaweb.memshell.packer.deserialize.hessian.HessianPacker;
import com.reajason.javaweb.memshell.packer.deserialize.hessian.HessianXSLTScriptEnginePacker;
import com.reajason.javaweb.memshell.packer.deserialize.java.*;
import com.reajason.javaweb.memshell.packer.el.ELPacker;
import com.reajason.javaweb.memshell.packer.freemarker.FreemarkerPacker;
import com.reajason.javaweb.memshell.packer.groovy.GroovyClassDefinerPacker;
import com.reajason.javaweb.memshell.packer.groovy.GroovyPacker;
import com.reajason.javaweb.memshell.packer.groovy.GroovyScriptEnginePacker;
import com.reajason.javaweb.memshell.packer.jar.AgentJarPacker;
import com.reajason.javaweb.memshell.packer.jar.DefaultJarPacker;
import com.reajason.javaweb.memshell.packer.jexl.JEXLPacker;
import com.reajason.javaweb.memshell.packer.jinjava.JinJavaPacker;
import com.reajason.javaweb.memshell.packer.jsp.DefalutJspPacker;
import com.reajason.javaweb.memshell.packer.jsp.JspPacker;
import com.reajason.javaweb.memshell.packer.jsp.JspxPacker;
import com.reajason.javaweb.memshell.packer.jxpath.JXPathPacker;
import com.reajason.javaweb.memshell.packer.mvel.MVELPacker;
import com.reajason.javaweb.memshell.packer.ognl.OGNLPacker;
import com.reajason.javaweb.memshell.packer.rhino.RhinoPacker;
import com.reajason.javaweb.memshell.packer.scriptengine.ScriptEnginePacker;
import com.reajason.javaweb.memshell.packer.spel.SpELPacker;
import com.reajason.javaweb.memshell.packer.spel.SpELScriptEnginePacker;
import com.reajason.javaweb.memshell.packer.spel.SpELSpringIOUtilsGzipPacker;
import com.reajason.javaweb.memshell.packer.spel.SpELSpringUtilsPacker;
import com.reajason.javaweb.memshell.packer.velocity.VelocityPacker;
import lombok.Getter;

import java.util.List;
import java.util.Objects;
import java.util.stream.Collectors;
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
    Rhino(new RhinoPacker()),

    /**
     * EL
     */
    EL(new ELPacker()),
    OGNL(new OGNLPacker()),
    MVEL(new MVELPacker()),
    Aviator(new AviatorPacker()),
    JXPath(new JXPathPacker()),
    JEXL(new JEXLPacker()),
    BeanShell(new BeanShellPacker()),

    SpEL(new SpELPacker()),
    SpELScriptEngine(new SpELScriptEnginePacker(), SpELPacker.class),
    SpELSpringIOUtils(new SpELSpringIOUtilsGzipPacker(), SpELPacker.class),
    SpELSpringUtils(new SpELSpringUtilsPacker(), SpELPacker.class),

    Groovy(new GroovyPacker()),
    GroovyClassDefiner(new GroovyClassDefinerPacker(), GroovyPacker.class),
    GroovyScriptEngine(new GroovyScriptEnginePacker(), GroovyPacker.class),

    Freemarker(new FreemarkerPacker()),
    Velocity(new VelocityPacker()),
    JinJava(new JinJavaPacker()),

    /**
     * Java 反序列化打包器
     */
    JavaDeserialize(new JavaDeserializePacker()),
    JavaCommonsBeanutils19(new CommonsBeanutils19Packer(), JavaDeserializePacker.class),
    JavaCommonsBeanutils18(new CommonsBeanutils18Packer(), JavaDeserializePacker.class),
    JavaCommonsBeanutils17(new CommonsBeanutils18Packer(), JavaDeserializePacker.class),
    JavaCommonsBeanutils16(new CommonsBeanutils16Packer(), JavaDeserializePacker.class),
    JavaCommonsBeanutils110(new CommonsBeanutils110Packer(), JavaDeserializePacker.class),
    JavaCommonsCollections3(new CommonsCollections3Packer(), JavaDeserializePacker.class),
    JavaCommonsCollections4(new CommonsCollections4Packer(), JavaDeserializePacker.class),

    /**
     * Hessian 反序列化打包器
     */
    Hessian2Deserialize(new Hessian2Packer()),
    Hessian2XSLTScriptEngine(new Hessian2XSLTScriptEnginePacker(), Hessian2Packer.class),

    HessianDeserialize(new HessianPacker()),
    HessianXSLTScriptEngine(new HessianXSLTScriptEnginePacker(), HessianPacker.class),

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
        return Stream.of(Packers.values()).filter(p -> Objects.equals(p.getParentPacker(), parentPacker)).collect(Collectors.toList());
    }
}
