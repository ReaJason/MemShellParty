package com.reajason.javaweb.packer.base64;

import com.reajason.javaweb.packer.ClassPackerConfig;
import com.reajason.javaweb.packer.Packer;
import lombok.SneakyThrows;

import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;

/**
 * @author ReaJason
 * @since 2025/9/2
 */
public class Base64URLEncoded implements Packer {

    @Override
    @SneakyThrows
    public String pack(ClassPackerConfig config) {
        return URLEncoder.encode(config.getClassBytesBase64Str(), StandardCharsets.UTF_8.name());
    }
}
