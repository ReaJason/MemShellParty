package com.reajason.javaweb.packer;

import com.reajason.javaweb.packer.aviator.AviatorPacker;
import com.reajason.javaweb.packer.base64.Base64Packer;
import com.reajason.javaweb.packer.base64.Base64URLEncoded;
import com.reajason.javaweb.packer.base64.DefaultBase64Packer;
import com.reajason.javaweb.packer.base64.GzipBase64Packer;
import com.reajason.javaweb.packer.bsh.BeanShellPacker;
import com.reajason.javaweb.packer.deserialize.hessian.Hessian2Packer;
import com.reajason.javaweb.packer.deserialize.hessian.Hessian2XSLTScriptEnginePacker;
import com.reajason.javaweb.packer.deserialize.hessian.HessianPacker;
import com.reajason.javaweb.packer.deserialize.hessian.HessianXSLTScriptEnginePacker;
import com.reajason.javaweb.packer.deserialize.java.*;
import com.reajason.javaweb.packer.el.ELPacker;
import com.reajason.javaweb.packer.freemarker.FreemarkerPacker;
import com.reajason.javaweb.packer.groovy.GroovyClassDefinerPacker;
import com.reajason.javaweb.packer.groovy.GroovyPacker;
import com.reajason.javaweb.packer.groovy.GroovyScriptEnginePacker;
import com.reajason.javaweb.packer.h2.H2JSPacker;
import com.reajason.javaweb.packer.h2.H2JavacPacker;
import com.reajason.javaweb.packer.h2.H2Packer;
import com.reajason.javaweb.packer.jar.*;
import com.reajason.javaweb.packer.jexl.JEXLPacker;
import com.reajason.javaweb.packer.jinjava.JinJavaPacker;
import com.reajason.javaweb.packer.jsp.ClassLoaderJspPacker;
import com.reajason.javaweb.packer.jsp.DefineClassJspPacker;
import com.reajason.javaweb.packer.jsp.JspPacker;
import com.reajason.javaweb.packer.jsp.JspxPacker;
import com.reajason.javaweb.packer.jxpath.JXPathPacker;
import com.reajason.javaweb.packer.jxpath.JXPathScriptEnginePacker;
import com.reajason.javaweb.packer.jxpath.JXPathSpringGzipJDK17Packer;
import com.reajason.javaweb.packer.jxpath.JXPathSpringGzipPacker;
import com.reajason.javaweb.packer.mvel.MVELPacker;
import com.reajason.javaweb.packer.ognl.OGNLPacker;
import com.reajason.javaweb.packer.ognl.OGNLScriptEnginePacker;
import com.reajason.javaweb.packer.ognl.OGNLSpringGzipJDK17Packer;
import com.reajason.javaweb.packer.ognl.OGNLSpringGzipPacker;
import com.reajason.javaweb.packer.rhino.RhinoPacker;
import com.reajason.javaweb.packer.scriptengine.DefaultScriptEnginePacker;
import com.reajason.javaweb.packer.scriptengine.ScriptEngineBigIntegerPacker;
import com.reajason.javaweb.packer.scriptengine.ScriptEngineNoSquareBracketsPacker;
import com.reajason.javaweb.packer.scriptengine.ScriptEnginePacker;
import com.reajason.javaweb.packer.spel.SpELPacker;
import com.reajason.javaweb.packer.spel.SpELScriptEnginePacker;
import com.reajason.javaweb.packer.spel.SpELSpringGzipJDK17Packer;
import com.reajason.javaweb.packer.spel.SpELSpringGzipPacker;
import com.reajason.javaweb.packer.translet.AbstractTransletPacker;
import com.reajason.javaweb.packer.translet.JDKAbstractTransletPacker;
import com.reajason.javaweb.packer.translet.OracleAbstractTransletPacker;
import com.reajason.javaweb.packer.translet.XalanAbstractTransletPacker;
import com.reajason.javaweb.packer.velocity.VelocityPacker;
import com.reajason.javaweb.packer.xmldecoder.XMLDecoderDefineClassPacker;
import com.reajason.javaweb.packer.xmldecoder.XMLDecoderPacker;
import com.reajason.javaweb.packer.xmldecoder.XMLDecoderScriptEnginePacker;
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
    Base64URLEncoded(new Base64URLEncoded(), Base64Packer.class),
    GzipBase64(new GzipBase64Packer(), Base64Packer.class),

    /**
     * JSP 打包器
     */
    JSP(new JspPacker()),
    ClassLoaderJSP(new ClassLoaderJspPacker(), JspPacker.class),
    DefineClassJSP(new DefineClassJspPacker(), JspPacker.class),
    JSPX(new JspxPacker(), JspPacker.class),

    /**
     * BigInteger
     */
    BigInteger(new BigIntegerPacker()),

    /**
     * BCEL
     */
    BCEL(new BCELPacker()),

    AbstractTranslet(new AbstractTransletPacker()),
    JDKAbstractTransletPacker(new JDKAbstractTransletPacker(), AbstractTransletPacker.class),
    XalanAbstractTransletPacker(new XalanAbstractTransletPacker(), AbstractTransletPacker.class),
    OracleAbstractTransletPacker(new OracleAbstractTransletPacker(), AbstractTransletPacker.class),

    /**
     * 脚本引擎打包器
     */
    ScriptEngine(new ScriptEnginePacker()),
    DefaultScriptEngine(new DefaultScriptEnginePacker(), ScriptEnginePacker.class),
    ScriptEngineNoSquareBrackets(new ScriptEngineNoSquareBracketsPacker(), ScriptEnginePacker.class),
    ScriptEngineBigInteger(new ScriptEngineBigIntegerPacker(), ScriptEnginePacker.class),

    Rhino(new RhinoPacker()),

    /**
     * EL
     */
    EL(new ELPacker()),

    OGNL(new OGNLPacker()),
    OGNLScriptEngine(new OGNLScriptEnginePacker(), OGNLPacker.class),
    OGNLSpringGzip(new OGNLSpringGzipPacker(), OGNLPacker.class),
    OGNLSpringGzipJDK17(new OGNLSpringGzipJDK17Packer(), OGNLPacker.class),

    MVEL(new MVELPacker()),
    Aviator(new AviatorPacker()),

    JXPath(new JXPathPacker()),
    JXPathScriptEngine(new JXPathScriptEnginePacker(), JXPathPacker.class),
    JXPathSpringGzip(new JXPathSpringGzipPacker(), JXPathPacker.class),
    JXPathSpringGzipJDK17(new JXPathSpringGzipJDK17Packer(), JXPathPacker.class),


    JEXL(new JEXLPacker()),
    BeanShell(new BeanShellPacker()),

    SpEL(new SpELPacker()),
    SpELScriptEngine(new SpELScriptEnginePacker(), SpELPacker.class),
    SpELSpringGzip(new SpELSpringGzipPacker(), SpELPacker.class),
    SpELSpringGzipJDK17(new SpELSpringGzipJDK17Packer(), SpELPacker.class),

    Groovy(new GroovyPacker()),
    GroovyClassDefiner(new GroovyClassDefinerPacker(), GroovyPacker.class),
    GroovyScriptEngine(new GroovyScriptEnginePacker(), GroovyPacker.class),

    Freemarker(new FreemarkerPacker()),
    Velocity(new VelocityPacker()),
    JinJava(new JinJavaPacker()),
    XMLDecoder(new XMLDecoderPacker()),
    XMLDecoderScriptEngine(new XMLDecoderScriptEnginePacker(), XMLDecoderPacker.class),
    XMLDecoderDefineClass(new XMLDecoderDefineClassPacker(), XMLDecoderPacker.class),

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
    AgentJarWithJDKAttacher(new AgentJarWithJDKAttacherPacker()),
    AgentJarWithJREAttacher(new AgentJarWithJREAttacherPacker()),

    H2(new H2Packer()),
    H2Javac(new H2JavacPacker(), H2Packer.class),
    H2JS(new H2JSPacker(), H2Packer.class),

    Jar(new DefaultJarPacker()),
    ScriptEngineJar(new ScriptEngineJarPacker()),

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

    public static List<Packers> getPackersWithParent(Class<?> parentPacker) {
        return Stream.of(Packers.values()).filter(p -> Objects.equals(p.getParentPacker(), parentPacker)).collect(Collectors.toList());
    }
}
