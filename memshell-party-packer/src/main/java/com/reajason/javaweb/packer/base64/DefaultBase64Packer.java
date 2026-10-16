package com.reajason.javaweb.packer.base64;

import com.reajason.javaweb.packer.ClassPackerConfig;
import com.reajason.javaweb.packer.Packer;

/**
 * @author ReaJason
 * @since 2024/12/17
 */
public class DefaultBase64Packer implements Packer {
    @Override
    public String pack(ClassPackerConfig config) {
        return config.getClassBytesBase64Str();
    }
}