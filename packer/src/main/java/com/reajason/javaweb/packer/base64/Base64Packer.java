package com.reajason.javaweb.packer.base64;

import com.reajason.javaweb.packer.ClassPackerConfig;
import com.reajason.javaweb.packer.Packer;
import com.reajason.javaweb.packer.Util;
import com.reajason.javaweb.packer.spec.PackerSchema;
import lombok.SneakyThrows;
import org.apache.commons.codec.binary.Base64;

import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.Objects;

/**
 * @author ReaJason
 * @since 2024/12/17
 */
public class Base64Packer implements Packer<Base64CustomPackerConfig> {

    @Override
    @SneakyThrows
    public String pack(ClassPackerConfig<Base64CustomPackerConfig> config) {
        Base64CustomPackerConfig customConfig = config.getCustomConfig();
        if (Objects.isNull(customConfig)) {
            return config.getClassBytesBase64Str();
        }
        byte[] bytes = config.getClassBytes();
        if (customConfig.isGzipCompressed()) {
            bytes = Util.gzipCompress(bytes);
        }
        String base64 = Base64.encodeBase64String(bytes);
        if (customConfig.isUrlEncoded()) {
            return URLEncoder.encode(base64, StandardCharsets.UTF_8.name());
        }
        return base64;
    }

    @Override
    public PackerSchema schema() {
        return Base64CustomPackerConfig.schema();
    }
}
