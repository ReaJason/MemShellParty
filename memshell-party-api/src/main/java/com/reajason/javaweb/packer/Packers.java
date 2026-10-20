package com.reajason.javaweb.packer;

/**
 * 打包方式名称常量，类似 {@code ShellType}/{@code ShellTool}：只提供编译期字符串，
 * 不持有任何 packer 实例，实际注册仍由 {@link PackerMeta} + {@code ServiceLoader} 完成。
 *
 * <p>这里同时包含分组名（如 {@link #Base64}、{@link #JSP}）和具体 packer 名。
 * 分组名只用于两级展示目录，不要求存在同名 packer：例如 {@link #Base64} 分组下是
 * {@link #DefaultBase64}、{@link #Base64URLEncoded}、{@link #GzipBase64}，
 * 只有注册过的名称才能直接作为打包方式使用。
 *
 * @author ReaJason
 * @since 2025/1/23
 */
public class Packers {

    /**
     * Base64
     */
    public static final String Base64 = "Base64";
    public static final String DefaultBase64 = "DefaultBase64";
    public static final String Base64URLEncoded = "Base64URLEncoded";
    public static final String GzipBase64 = "GzipBase64";

    /**
     * JSP 打包器
     */
    public static final String JSP = "JSP";
    public static final String ClassLoaderJSP = "ClassLoaderJSP";
    public static final String ClassLoaderJSPUnicode = "ClassLoaderJSPUnicode";
    public static final String DefineClassJSP = "DefineClassJSP";
    public static final String DefineClassJSPUnicode = "DefineClassJSPUnicode";
    public static final String JSPX = "JSPX";
    public static final String JSPXUnicode = "JSPXUnicode";

    /**
     * BigInteger
     */
    public static final String BigInteger = "BigInteger";

    /**
     * BCEL
     */
    public static final String BCEL = "BCEL";

    public static final String AbstractTranslet = "AbstractTranslet";
    public static final String JDKAbstractTransletPacker = "JDKAbstractTransletPacker";
    public static final String XalanAbstractTransletPacker = "XalanAbstractTransletPacker";
    public static final String OracleAbstractTransletPacker = "OracleAbstractTransletPacker";

    /**
     * 脚本引擎打包器
     */
    public static final String ScriptEngine = "ScriptEngine";
    public static final String DefaultScriptEngine = "DefaultScriptEngine";
    public static final String ScriptEngineNoSquareBrackets = "ScriptEngineNoSquareBrackets";
    public static final String ScriptEngineBigInteger = "ScriptEngineBigInteger";

    public static final String Rhino = "Rhino";

    /**
     * EL
     */
    public static final String EL = "EL";

    public static final String OGNL = "OGNL";
    public static final String OGNLScriptEngine = "OGNLScriptEngine";
    public static final String OGNLSpringGzip = "OGNLSpringGzip";
    public static final String OGNLSpringGzipJDK17 = "OGNLSpringGzipJDK17";

    public static final String MVEL = "MVEL";
    public static final String Aviator = "Aviator";

    public static final String JXPath = "JXPath";
    public static final String JXPathScriptEngine = "JXPathScriptEngine";
    public static final String JXPathSpringGzip = "JXPathSpringGzip";
    public static final String JXPathSpringGzipJDK17 = "JXPathSpringGzipJDK17";

    public static final String JEXL = "JEXL";
    public static final String BeanShell = "BeanShell";

    public static final String SpEL = "SpEL";
    public static final String SpELScriptEngine = "SpELScriptEngine";
    public static final String SpELSpringGzip = "SpELSpringGzip";
    public static final String SpELSpringGzipJDK17 = "SpELSpringGzipJDK17";

    public static final String Groovy = "Groovy";
    public static final String GroovyClassDefiner = "GroovyClassDefiner";
    public static final String GroovyScriptEngine = "GroovyScriptEngine";

    public static final String Freemarker = "Freemarker";
    public static final String FreemarkerScriptEngine = "FreemarkerScriptEngine";
    public static final String FreemarkerSpELSpringGzip = "FreemarkerSpELSpringGzip";
    public static final String FreemarkerSpELSpringGzipJDK17 = "FreemarkerSpELSpringGzipJDK17";
    public static final String Velocity = "Velocity";
    public static final String JinJava = "JinJava";
    public static final String XMLDecoder = "XMLDecoder";
    public static final String XMLDecoderScriptEngine = "XMLDecoderScriptEngine";
    public static final String XMLDecoderDefineClass = "XMLDecoderDefineClass";

    /**
     * XSLT 打包器
     */
    public static final String XSLT = "XSLT";
    public static final String XSLTScriptEngine = "XSLTScriptEngine";

    /**
     * Java 反序列化打包器
     */
    public static final String JavaDeserialize = "JavaDeserialize";
    public static final String JavaCommonsBeanutils19 = "JavaCommonsBeanutils19";
    public static final String JavaCommonsBeanutils18 = "JavaCommonsBeanutils18";
    public static final String JavaCommonsBeanutils17 = "JavaCommonsBeanutils17";
    public static final String JavaCommonsBeanutils16 = "JavaCommonsBeanutils16";
    public static final String JavaCommonsBeanutils110 = "JavaCommonsBeanutils110";
    public static final String JavaCommonsCollections3 = "JavaCommonsCollections3";
    public static final String JavaCommonsCollections4 = "JavaCommonsCollections4";

    /**
     * Hessian 反序列化打包器
     */
    public static final String Hessian2Deserialize = "Hessian2Deserialize";
    public static final String Hessian2XSLTScriptEngine = "Hessian2XSLTScriptEngine";

    public static final String HessianDeserialize = "HessianDeserialize";
    public static final String HessianXSLTScriptEngine = "HessianXSLTScriptEngine";

    public static final String AgentJar = "AgentJar";
    public static final String AgentJarWithJDKAttacher = "AgentJarWithJDKAttacher";
    public static final String AgentJarWithJREAttacher = "AgentJarWithJREAttacher";

    public static final String H2 = "H2";
    public static final String H2Javac = "H2Javac";
    public static final String H2JS = "H2JS";
    public static final String H2JSURLEncode = "H2JSURLEncode";

    public static final String Jar = "Jar";
    public static final String ScriptEngineJar = "ScriptEngineJar";
    public static final String GroovyTransformJar = "GroovyTransformJar";

    public static final String XxlJob = "XxlJob";
    public static final String XxlJobJson = "XxlJobJson";
    public static final String XxlJobHessian = "XxlJobHessian";
}
